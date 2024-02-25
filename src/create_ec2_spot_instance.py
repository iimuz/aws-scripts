"""開発用のEC2インスタンスを作成するときのスクリプト.

利用例:

```sh
`python src/create_ec2_spot_instance.py \
    -vv src/create_ec2_config.yml \
    --profile AWS_PROFILE
```
"""
import logging
import sys
import time
from argparse import ArgumentParser
from logging import Formatter, StreamHandler
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Self

import boto3
import yaml
from mypy_boto3_ec2.literals import (
    HostnameTypeType,
    HttpTokensStateType,
    InstanceMetadataEndpointStateType,
    InstanceTypeType,
    MarketTypeType,
    ResourceTypeType,
    SpotInstanceTypeType,
    VolumeTypeType,
)
from mypy_boto3_ec2.type_defs import (
    BlockDeviceMappingTypeDef,
    EbsBlockDeviceTypeDef,
    InstanceMarketOptionsRequestTypeDef,
    InstanceMetadataOptionsRequestTypeDef,
    InstanceNetworkInterfaceSpecificationTypeDef,
    PrivateDnsNameOptionsRequestTypeDef,
    SpotMarketOptionsTypeDef,
    TagSpecificationTypeDef,
    TagTypeDef,
)
from pydantic import BaseModel, ConfigDict, Field

_logger = logging.getLogger(__name__)


class _RunConfig(BaseModel):
    """スクリプト実行のためのオプション."""

    settings_path: Path = Field(help="設定ファイルのパス.")
    profile: str = Field(help="AWS Profile.")

    verbosity: int = Field(help="ログレベル.")

    model_config = ConfigDict(frozen=True)


class _AttachVolumesSettings(BaseModel):
    volume_id: str
    device_name: str


class _EBS(BaseModel):
    """EBSボリュームの設定."""

    snapshot_id: str = Field(
        default="snap-0ae02beb4873352c7",  # cpu ubuntu
        serialization_alias="SnapshotId",
    )
    delete_on_termination: bool = Field(
        default=True,
        serialization_alias="DeleteOnTermination",
    )
    volume_type: VolumeTypeType = Field(default="gp3", serialization_alias="VolumeType")
    volume_size: int = Field(
        default=30,
        ge=8,
        serialization_alias="VolumeSize",
    )

    iops: int = Field(default=3000, serialization_alias="Iops")
    throughput: int = Field(default=125, serialization_alias="Throughput")

    model_config = ConfigDict(frozen=True)

    def to_ebs(self: Self) -> EbsBlockDeviceTypeDef:
        return EbsBlockDeviceTypeDef(
            SnapshotId=self.snapshot_id,
            DeleteOnTermination=self.delete_on_termination,
            VolumeType=self.volume_type,
            VolumeSize=self.volume_size,
            Iops=self.iops,
            Throughput=self.throughput,
        )


class _Settings(BaseModel):
    ami: str
    instance_name: str
    instance_type: InstanceTypeType

    # Volumes
    root_volume: _EBS = Field(_EBS(), help="ルートボリュームの設定.")
    attach_volumes: list[_AttachVolumesSettings] | None

    # Network
    nic_groups: list[str] = Field(default_factory=list)

    # Security
    ssh_key_name: str

    model_config = ConfigDict(frozen=True)


class _BlockDevice(BaseModel):
    """ブロックストレージの設定."""

    device_name: str = Field(
        default="/dev/sda1",
        serialization_alias="DeviceName",
    )
    ebs: _EBS = Field(
        default_factory=lambda: _EBS(),
        serialization_alias="Ebs",
    )

    model_config = ConfigDict(frozen=True)

    def to_block_device_mapping(self: Self) -> BlockDeviceMappingTypeDef:
        return BlockDeviceMappingTypeDef(
            DeviceName=self.device_name, Ebs=self.ebs.to_ebs()
        )


class _AttachVolume(BaseModel):
    volume_id: str = Field("vol-xxxxxxxxxxxxxxxxx")
    device_name: str = Field("/dev/xvdb")


class _TagSpecificationTag(BaseModel):
    key: str = Field(serialization_alias="Key")
    value: str = Field(serialization_alias="Value")

    model_config = ConfigDict(frozen=True)

    def to_tag(self: Self) -> TagTypeDef:
        return TagTypeDef(
            Key=self.key,
            Value=self.value,
        )


class _TagSpecifications(BaseModel):
    resource_type: ResourceTypeType = Field(
        default="instance", serialization_alias="ResourceType"
    )
    tags: list[_TagSpecificationTag] = Field(
        default_factory=list, serialization_alias="Tags"
    )

    model_config = ConfigDict(frozen=True)

    def to_tag_specification(self: Self) -> TagSpecificationTypeDef:
        return TagSpecificationTypeDef(
            ResourceType=self.resource_type,
            Tags=[t.to_tag() for t in self.tags],
        )


class _SpotOptions(BaseModel):
    max_price: str | None = Field(
        default=None, serialization_alias="MaxPrice", exclude_none=True
    )
    spot_instance_type: SpotInstanceTypeType = Field(
        default="one-time",
        serialization_alias="SpotInstanceType",
    )

    model_config = ConfigDict(frozen=True)

    def to_spot_options(self: Self) -> SpotMarketOptionsTypeDef:
        if self.max_price is None:
            return SpotMarketOptionsTypeDef(
                SpotInstanceType=self.spot_instance_type,
            )

        return SpotMarketOptionsTypeDef(
            MaxPrice=self.max_price,
            SpotInstanceType=self.spot_instance_type,
        )


class _InstanceMarketOptions(BaseModel):
    market_type: MarketTypeType = Field(
        default="spot", serialization_alias="MarketType"
    )
    spot_options: _SpotOptions = Field(
        default_factory=lambda: _SpotOptions(),
        serialization_alias="SpotOptions",
    )

    model_config = ConfigDict(frozen=True)

    def to_instance_market_options(self: Self) -> InstanceMarketOptionsRequestTypeDef:
        return InstanceMarketOptionsRequestTypeDef(
            MarketType=self.market_type,
            SpotOptions=self.spot_options.to_spot_options(),
        )


class _NetworkInterface(BaseModel):
    associate_public_ip_address: bool = Field(
        default=True, serialization_alias="AssociatePublicIpAddress"
    )
    device_index: int = Field(default=0, serialization_alias="DeviceIndex")
    groups: list[str] = Field(default_factory=list, serialization_alias="Groups")

    model_config = ConfigDict(frozen=True)

    def to_network_interface(
        self: Self,
    ) -> InstanceNetworkInterfaceSpecificationTypeDef:
        return InstanceNetworkInterfaceSpecificationTypeDef(
            AssociatePublicIpAddress=self.associate_public_ip_address,
            DeviceIndex=self.device_index,
            Groups=self.groups,
        )


class _MetadataOptions(BaseModel):
    http_tokens: HttpTokensStateType = Field(
        default="required", serialization_alias="HttpTokens"
    )
    http_endpoint: InstanceMetadataEndpointStateType = Field(
        default="enabled", serialization_alias="HttpEndpoint"
    )
    http_put_response_hop_limit: int = Field(
        default=2, serialization_alias="HttpPutResponseHopLimit"
    )

    model_config = ConfigDict(frozen=True)

    def to_instance_metadata_options(
        self: Self,
    ) -> InstanceMetadataOptionsRequestTypeDef:
        return InstanceMetadataOptionsRequestTypeDef(
            HttpTokens=self.http_tokens,
            HttpEndpoint=self.http_endpoint,
            HttpPutResponseHopLimit=self.http_put_response_hop_limit,
        )


class _PrivateDnsNameOptions(BaseModel):
    host_name_type: HostnameTypeType = Field(
        default="ip-name", serialization_alias="HostnameType"
    )
    enable_resource_name_dns_a_record: bool = Field(
        default=True, serialization_alias="EnableResourceNameDnsARecord"
    )
    enable_resource_name_dns_aaaa_record: bool = Field(
        default=False, serialization_alias="EnableResourceNameDnsAAAARecord"
    )

    model_config = ConfigDict(frozen=True)

    def to_private_dns_name_options(
        self: Self,
    ) -> PrivateDnsNameOptionsRequestTypeDef:
        return PrivateDnsNameOptionsRequestTypeDef(
            HostnameType=self.host_name_type,
            EnableResourceNameDnsARecord=self.enable_resource_name_dns_a_record,
            EnableResourceNameDnsAAAARecord=self.enable_resource_name_dns_aaaa_record,
        )


def _main() -> None:
    """スクリプトのエントリポイント."""
    # 実行時引数の読み込み
    config = _parse_args()

    # ログ設定
    loglevel = {
        0: logging.ERROR,
        1: logging.WARNING,
        2: logging.INFO,
        3: logging.DEBUG,
    }.get(config.verbosity, logging.DEBUG)
    script_filepath = Path(__file__)
    log_filepath = Path("data/interim") / f"{script_filepath.stem}.log"
    log_filepath.parent.mkdir(exist_ok=True)
    _setup_logger(log_filepath, loglevel=loglevel)
    _logger.info(config)

    # 設定ファイルの読み込み
    with config.settings_path.open("rt") as f:
        settings = _Settings(**yaml.safe_load(f))

    # 設定値の作成
    tag_specifications = _TagSpecifications(
        tags=[_TagSpecificationTag(key="Name", value=settings.instance_name)]
    )
    block_device = _BlockDevice(ebs=settings.root_volume)
    attach_volumes: list[_AttachVolume] = []
    if settings.attach_volumes is not None:
        attach_volumes = [
            _AttachVolume(**v.model_dump()) for v in settings.attach_volumes
        ]
    instance_market_options = _InstanceMarketOptions()
    network_interface = _NetworkInterface(groups=settings.nic_groups)
    metadata_options = _MetadataOptions()
    private_dns_name_options = _PrivateDnsNameOptions()
    # 設定値のログ出力
    _logger.info(
        "tag specifications: %s", tag_specifications.model_dump_json(by_alias=True)
    )
    _logger.info(
        "block device: %s",
        block_device.model_dump_json(by_alias=True, exclude_none=True),
    )
    for index in range(len(attach_volumes)):
        _logger.info(
            "attach volumes[%d]: %s", index, attach_volumes[index].model_dump_json()
        )
    _logger.info(
        "instance market options: %s",
        instance_market_options.model_dump_json(by_alias=True),
    )
    _logger.info(
        "network interface: %s", network_interface.model_dump_json(by_alias=True)
    )
    _logger.info(
        "metadata options: %s", metadata_options.model_dump_json(by_alias=True)
    )
    _logger.info(
        "private dns name options: %s",
        private_dns_name_options.model_dump_json(by_alias=True),
    )

    # インスタンスの生成
    _logger.info("Launching EC2 ...")
    session = boto3.Session(profile_name=config.profile)
    ec2 = session.client("ec2")
    instances = ec2.run_instances(
        ImageId=settings.ami,
        MaxCount=1,
        MinCount=1,
        InstanceType=settings.instance_type,
        TagSpecifications=[tag_specifications.to_tag_specification()],
        KeyName=settings.ssh_key_name,
        InstanceMarketOptions=instance_market_options.to_instance_market_options(),
        BlockDeviceMappings=[block_device.to_block_device_mapping()],
        NetworkInterfaces=[network_interface.to_network_interface()],
        MetadataOptions=metadata_options.to_instance_metadata_options(),
        PrivateDnsNameOptions=private_dns_name_options.to_private_dns_name_options(),
    )
    time.sleep(5.0)
    instance = instances["Instances"][0]
    _logger.info(instance)

    # volumeをアタッチする前にインスタンスがrunningである必要があるため待つ
    _logger.info("wait for running...")
    for _ in range(100):
        time.sleep(1.0)  # 1秒待つ
        response = ec2.describe_instances(InstanceIds=[instance["InstanceId"]])
        state = response["Reservations"][0]["Instances"][0]["State"]["Name"]
        if state == "running":
            break
    if state != "running":
        message = "EC2 instance is not running."
        raise ValueError(message)

    # attach volume
    for volume in attach_volumes:
        ec2.attach_volume(
            InstanceId=instance["InstanceId"],
            VolumeId=volume.volume_id,
            Device=volume.device_name,
        )


def _parse_args() -> _RunConfig:
    """スクリプト実行のための引数を読み込む."""
    parser = ArgumentParser(description="EC2インスタンスを生成する.")

    parser.add_argument("settings_path", help="設定ファイルのパス.")
    parser.add_argument("-p", "--profile", help="AWS Profile.")

    parser.add_argument(
        "-v",
        "--verbosity",
        action="count",
        default=0,
        help="詳細メッセージのレベルを設定.",
    )

    args = parser.parse_args()

    return _RunConfig(**vars(args))


def _setup_logger(filepath: Path | None, loglevel: int) -> None:
    """ロガー設定を行う.

    Parameters
    ----------
    filepath : Path | None
        ログ出力するファイルパス. Noneの場合はファイル出力しない.

    loglevel : int
        出力するログレベル.

    Notes
    -----
    ファイル出力とコンソール出力を行うように設定する。

    """
    _logger.setLevel(loglevel)

    # consoleログ
    console_handler = StreamHandler()
    console_handler.setLevel(loglevel)
    console_handler.setFormatter(
        Formatter("[%(levelname)7s] %(asctime)s (%(name)s) %(message)s")
    )
    _logger.addHandler(console_handler)

    # ファイル出力するログ
    # 基本的に大量に利用することを想定していないので、ログファイルは多くは残さない。
    if filepath is not None:
        file_handler = RotatingFileHandler(
            filepath,
            encoding="utf-8",
            mode="a",
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=1,
        )
        file_handler.setLevel(loglevel)
        file_handler.setFormatter(
            Formatter("[%(levelname)7s] %(asctime)s (%(name)s) %(message)s")
        )
        _logger.addHandler(file_handler)


if __name__ == "__main__":
    try:
        _main()
    except Exception:
        _logger.exception("Unhandled error")
        sys.exit(1)
