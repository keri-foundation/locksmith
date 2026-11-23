"""SEDI source types and delegation evidence shown by the wallet."""
from collections.abc import Mapping
from functools import partial

from keri.acdc import chaining, evaluating


# The SEDI guide names these sources. Its Bespoke schema leaves their types open.
BESPOKE = 'EGcqmkrnaQz8F1PEekLOaySiW-uDaJ0SfoqtSuqCvEif'
BESPOKE_SOURCES = {
    'core': 'EN0JtdzBmFuTUzyJG9CXZhtdu-bW0V6L95bsVBzi-cY-',
    'residence': 'EH5hn7CbtDFxhS3IKioC8P-e4YyZoxqzhRpr4X_e32BD',
    'age': 'EPqXrwPT6b0_KghrrMuIdmuD68Aytv1XK6jU86EumgJV',
    'image': 'EKuGAkHNpj5ujsEWQuZFe8bbuSrIOwojUNjgirDtWIAb',
    'guardian': 'EDJzXg34opr6-odFix6lpiccfHF7ksITHuIES_MQRH4b',
    'social': 'EB8MUTKRg8284YPduyhDgUVvNM192-247KcRaXhIxoni',
}


DELEGATION_SCHEMAS = {
    'EBbOpBe0lP_epHhakeiXdOmeal3leDfLRf0PAItsanoQ',  # Organizational Unit
    'EGx4BLclkjhaK1501guyBifxuTTJLwuK61InBTdkKF7v',  # Issuing Agent
    BESPOKE_SOURCES['guardian'],
}


def schema_id(credential):
    schema = credential.schema
    return schema.get('$id') if isinstance(schema, Mapping) else schema


def _all_verified(reducer, members):
    # One valid OR member can authorize a Grant. It cannot verify its siblings.
    for member in members:
        if member.verdict != chaining.Verdicts.valid:
            return member
    return reducer(members)


class _DelegationReview(evaluating.EdgeEvaluator):
    """Collect delegation credentials in upstream-to-downstream order."""

    def __init__(self, evaluator):
        super().__init__(evaluator.schemaEvaluator, evaluator.verifyNode, evaluator.isDelegated,
                         reducers={op: partial(_all_verified, reducer) for op, reducer in evaluator.reducers.items()})
        self.sources = {}

    def _evaluateLeafEdge(self, group, *, nodes, **kwa):
        verdict = super()._evaluateLeafEdge(group, nodes=nodes, **kwa)
        if verdict is None or verdict.verdict != chaining.Verdicts.valid:
            return verdict
        far = nodes[group['n']].serder
        if schema_id(far) not in DELEGATION_SCHEMAS:
            return verdict
        operators = group.get('o') or []
        operators = [operators] if isinstance(operators, str) else operators
        delegative = next((op for op in reversed(operators) if op in evaluating.DelegativeEdgeOps), None)
        if delegative in ('I2I', 'DI2I') or (far.iseaid and not any(
                op in evaluating.DefaultSuppressingEdgeOps for op in operators)):
            self.sources[far.said] = far
        return verdict


def grant_delegations(vault, origin, nests):
    """Return verified delegation sources, or None when the evidence is incomplete."""
    nodes = {nest.serder.said: nest for nest in nests}
    if origin not in nodes:
        return None
    if not nodes[origin].serder.sad.get('e') or not any(
            schema_id(nest.serder) in DELEGATION_SCHEMAS for nest in nests):
        return []
    for nest in nests:
        # Native signature verification uses the in-memory key state cache.
        try:
            vault.hby.db.kevers[nest.serder.israid]
        except KeyError:
            pass
    review = _DelegationReview(vault.exc.routes['/ipex/grant'].edgeEvaluator)
    records = {}
    verdict = review.evaluate(origin, nodes=nodes, records=records)
    if (verdict is None or verdict.verdict != chaining.Verdicts.valid
            or any(record.state != 'issued' for record in records.values())):
        return None
    return list(review.sources.values())
