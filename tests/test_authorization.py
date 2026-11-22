from scanner.authz_intel.authorization.access_matrix import AccessMatrix
from scanner.authz_intel.authorization.policy_engine import AccessDecision, PolicyEngine
from scanner.authz_intel.inventory.lab_inventory import lab_objects, lab_principals
from scanner.authz_intel.inventory.object_registry import ObjectRecord


def test_lab_policy_owner_shared_tenant_and_admin():
    engine = PolicyEngine.load("configs/policies")
    principals = lab_principals()
    objects = lab_objects()
    alice_private = objects.get("documents", "1001")
    shared = objects.get("documents", "1002")
    charlie_private = objects.get("documents", "3001")

    assert engine.evaluate_access(principals.get("alice"), alice_private, "read") is AccessDecision.ALLOWED
    assert engine.evaluate_access(principals.get("bob"), shared, "read") is AccessDecision.ALLOWED
    assert engine.evaluate_access(principals.get("charlie"), shared, "read") is AccessDecision.DENIED
    assert engine.evaluate_access(principals.get("bob"), alice_private, "read") is AccessDecision.DENIED
    assert engine.evaluate_access(principals.get("admin"), charlie_private, "read") is AccessDecision.DENIED


def test_write_and_delete_require_owner_or_explicit_policy():
    engine = PolicyEngine.load("configs/policies")
    principals = lab_principals()
    shared = lab_objects().get("documents", "1002")

    assert engine.evaluate_access(principals.get("bob"), shared, "update") is AccessDecision.ALLOWED
    assert engine.evaluate_access(principals.get("bob"), shared, "delete") is AccessDecision.DENIED
    assert engine.evaluate_access(principals.get("charlie"), shared, "update") is AccessDecision.DENIED


def test_missing_policy_is_inconclusive_and_matrix_is_complete():
    engine = PolicyEngine.load("configs/policies")
    principals = lab_principals()
    objects = lab_objects()
    unknown = ObjectRecord("7001", "invoices", "admin", "tenant-a", "private")

    assert engine.evaluate_access(principals.get("alice"), unknown, "read") is AccessDecision.INCONCLUSIVE
    matrix = AccessMatrix(engine).evaluate(
        principals.all(),
        objects.for_type("documents"),
        ("read", "update", "delete"),
    )
    assert len(matrix) == 4 * 4 * 3
