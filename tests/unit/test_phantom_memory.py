import pytest
from slopguard.memory.phantom import PhantomMemory
from slopguard.core.models import Ecosystem, PhantomState, RegistryStatus

def test_phantom_lifecycle(tmp_path):
    storage = tmp_path / "phantoms.json"
    memory = PhantomMemory(storage_path=str(storage))

    pkg = "hallucinated-ai-model-lib"
    eco = Ecosystem.PYPI

    # Observation 1: NOT_FOUND
    rec1 = memory.record_observation(pkg, eco, RegistryStatus.NOT_FOUND)
    assert rec1.current_state == PhantomState.NOT_FOUND
    assert rec1.occurrence_count == 1

    # Observation 2: Still NOT_FOUND
    rec2 = memory.record_observation(pkg, eco, RegistryStatus.NOT_FOUND)
    assert rec2.occurrence_count == 2
    assert rec2.current_state == PhantomState.NOT_FOUND

    # Observation 3: An attacker now registered the package! Registry returns FOUND!
    rec3 = memory.record_observation(pkg, eco, RegistryStatus.FOUND)
    assert rec3.current_state == PhantomState.APPEARED
    assert rec3.previous_state == PhantomState.NOT_FOUND
    assert len(rec3.transitions) == 1
    assert rec3.transitions[0].to_state == PhantomState.APPEARED

    # Verify persistence
    new_mem = PhantomMemory(storage_path=str(storage))
    loaded = new_mem.get_record(pkg, eco)
    assert loaded is not None
    assert loaded.current_state == PhantomState.APPEARED
