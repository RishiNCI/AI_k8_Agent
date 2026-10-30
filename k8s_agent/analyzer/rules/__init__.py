from k8s_agent.analyzer.rules.base import BaseRule, PatternMatcher
from k8s_agent.analyzer.rules.oom import OOMRule
from k8s_agent.analyzer.rules.crashloop import CrashLoopRule
from k8s_agent.analyzer.rules.probes import ProbeRule
from k8s_agent.analyzer.rules.networking import NetworkDnsRule
from k8s_agent.analyzer.rules.image_pull import ImagePullRule
from k8s_agent.analyzer.rules.storage import StorageRule
from k8s_agent.analyzer.rules.config import ConfigSecretRule
from k8s_agent.analyzer.rules.rbac import RbacRule
from k8s_agent.analyzer.rules.resource_deadlock import ResourceDeadlockRule
from k8s_agent.analyzer.rules.panic import PanicRule

ALL_RULES = [
    OOMRule(),
    CrashLoopRule(),
    ProbeRule(),
    NetworkDnsRule(),
    ImagePullRule(),
    StorageRule(),
    ConfigSecretRule(),
    RbacRule(),
    ResourceDeadlockRule(),
    PanicRule(),
]

__all__ = [
    "BaseRule",
    "PatternMatcher",
    "OOMRule",
    "CrashLoopRule",
    "ProbeRule",
    "NetworkDnsRule",
    "ImagePullRule",
    "StorageRule",
    "ConfigSecretRule",
    "RbacRule",
    "ResourceDeadlockRule",
    "PanicRule",
    "ALL_RULES",
]
