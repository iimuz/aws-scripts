"""開発用のEC2インスタンスを作成するときのスクリプト.

利用例: `python src/create_ec2_spot_instance.py -vv src/create_ec2_config.yml --profile AWS_PROFILE`
"""
import logging
import sys
import time
from argparse import ArgumentParser
from logging import Formatter, StreamHandler
from logging.handlers import RotatingFileHandler
from pathlib import Path

import boto3
import yaml
from pydantic import BaseModel, ConfigDict, Field

_logger = logging.getLogger(__name__)


class _RunConfig(BaseModel):
    """スクリプト実行のためのオプション."""

    settings_path: Path = Field(help="設定ファイルのパス.")
    profile: str = Field(help="AWS Profile.")

    verbosity: int = Field(help="ログレベル.")

    model_config = ConfigDict(frozen=True)


class _Settings(BaseModel):
    ami: str
    instance_name: str
    instance_type: str

    # Volumes
    root_volume_size: int = Field(30, ge=8, help="ルートボリュームのサイズ(GB).")

    # Network
    nic_groups: list[str] = Field(default_factory=lambda: list())

    # Security
    ssh_key_name: str

    model_config = ConfigDict(frozen=True)


class _EBS(BaseModel):
    """EBSボリュームの設定."""

    snapshot_id: str = Field(
        "snap-0ae02beb4873352c7",
        serialization_alias="SnapshotId",
    )
    delete_on_termination: bool = Field(
        True,
        serialization_alias="DeleteOnTermination",
    )
    volume_type: str = Field("gp3", serialization_alias="VolumeType")
    volume_size: int = Field(
        30,
        ge=8,
        serialization_alias="VolumeSize",
    )

    model_config = ConfigDict(frozen=True)


class _BlockDevice(BaseModel):
    """ブロックストレージの設定."""

    device_name: str = Field(
        "/dev/sda1",
        serialization_alias="DeviceName",
    )
    ebs: _EBS = Field(
        default_factory=lambda: _EBS(),
        serialization_alias="Ebs",
    )

    model_config = ConfigDict(frozen=True)


class _TagSpecificationTag(BaseModel):
    key: str = Field(serialization_alias="Key")
    value: str = Field(serialization_alias="Value")

    model_config = ConfigDict(frozen=True)


class _TagSpecifications(BaseModel):
    resource_type: str = Field("instance", serialization_alias="ResourceType")
    tags: list[_TagSpecificationTag] = Field(
        default_factory=lambda: list(), serialization_alias="Tags"
    )

    model_config = ConfigDict(frozen=True)


class _SpotOptions(BaseModel):
    max_price: str | None = Field(
        None, serialization_alias="MaxPrice", exclude_none=True
    )
    spot_instance_type: str = Field(
        "one-time",
        serialization_alias="SpotInstanceType",
    )

    model_config = ConfigDict(frozen=True)


class _InstanceMarketOptions(BaseModel):
    market_type: str = Field("spot", serialization_alias="MarketType")
    spot_options: _SpotOptions = Field(
        default_factory=lambda: _SpotOptions(),
        serialization_alias="SpotOptions",
    )

    model_config = ConfigDict(frozen=True)


class _NetworkInterface(BaseModel):
    associate_public_ip_address: bool = Field(
        True, serialization_alias="AssociatePublicIpAddress"
    )
    device_index: int = Field(0, serialization_alias="DeviceIndex")
    groups: list[str] = Field(
        default_factory=lambda: list(), serialization_alias="Groups"
    )

    model_config = ConfigDict(frozen=True)


class _MetadataOptions(BaseModel):
    http_tokens: str = Field("required", serialization_alias="HttpTokens")
    http_endpoint: str = Field("enabled", serialization_alias="HttpEndpoint")
    http_put_response_hop_limit: int = Field(
        2, serialization_alias="HttpPutResponseHopLimit"
    )

    model_config = ConfigDict(frozen=True)


class _PrivateDnsNameOptions(BaseModel):
    host_name_type: str = Field("ip-name", serialization_alias="HostnameType")
    enable_resource_name_dns_a_record: bool = Field(
        True, serialization_alias="EnableResourceNameDnsARecord"
    )
    enable_resource_name_dns_aaaa_record: bool = Field(
        False, serialization_alias="EnableResourceNameDnsAAAARecord"
    )

    model_config = ConfigDict(frozen=True)


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
    block_device = _BlockDevice(
        ebs=_EBS(volume_size=settings.root_volume_size),
    )
    instance_market_options = _InstanceMarketOptions()
    network_interface = _NetworkInterface(groups=settings.nic_groups)
    metadata_options = _MetadataOptions()
    private_dns_name_options = _PrivateDnsNameOptions()
    # 設定値のログ出力
    _logger.info(
        "tag specifications: {}".format(
            tag_specifications.model_dump_json(by_alias=True)
        )
    )
    _logger.info(
        "block device: {}".format(
            block_device.model_dump_json(by_alias=True),
        )
    )
    _logger.info(
        "instance market options: {}".format(
            instance_market_options.model_dump_json(by_alias=True)
        )
    )
    _logger.info(
        "network interface: {}".format(
            network_interface.model_dump_json(by_alias=True),
        )
    )
    _logger.info(
        "metadata options: {}".format(
            metadata_options.model_dump_json(by_alias=True),
        )
    )
    _logger.info(
        "private dns name options: {}".format(
            private_dns_name_options.model_dump_json(by_alias=True)
        )
    )

    # インスタンスの生成
    _logger.info("Launching EC2 ...")
    session = boto3.Session(profile_name=config.profile)
    ec2_resource = session.resource("ec2")
    instances = ec2_resource.create_instances(
        ImageId=settings.ami,
        MaxCount=1,
        MinCount=1,
        InstanceType=settings.instance_type,
        TagSpecifications=[tag_specifications.model_dump(by_alias=True)],
        KeyName=settings.ssh_key_name,
        InstanceMarketOptions=instance_market_options.model_dump(
            by_alias=True, exclude_none=True
        ),
        BlockDeviceMappings=[block_device.model_dump(by_alias=True)],
        NetworkInterfaces=[network_interface.model_dump(by_alias=True)],
        MetadataOptions=metadata_options.model_dump(by_alias=True),
        PrivateDnsNameOptions=private_dns_name_options.model_dump(
            by_alias=True,
        ),
    )
    time.sleep(5.0)
    instance = instances[0]
    _logger.info(instance)


def _parse_args() -> _RunConfig:
    """スクリプト実行のための引数を読み込む."""
    parser = ArgumentParser(description="EC2インスタンスを生成する.")

    parser.add_argument("settings_path", help="設定ファイルのパス.")
    parser.add_argument("-p", "--profile", help="AWS Profile.")

    parser.add_argument(
        "-v", "--verbosity", action="count", default=0, help="詳細メッセージのレベルを設定."
    )

    args = parser.parse_args()
    config = _RunConfig(**vars(args))

    return config


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
    except Exception as e:
        _logger.exception(e)
        sys.exit(1)
