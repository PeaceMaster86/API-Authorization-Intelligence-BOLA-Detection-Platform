from .object_registry import ObjectRecord, ObjectRegistry
from .principal_registry import Principal, PrincipalRegistry
from .lab_inventory import lab_objects, lab_principals

__all__ = [
    "ObjectRecord",
    "ObjectRegistry",
    "Principal",
    "PrincipalRegistry",
    "lab_objects",
    "lab_principals",
]
