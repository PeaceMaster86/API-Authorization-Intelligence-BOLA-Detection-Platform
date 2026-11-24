# Limitations and future work

- The lab fixture store is in-memory; PostgreSQL persistence and Alembic
  migrations are planned but not implemented.
- The scanner currently focuses on configured document and nested-task lab
  routes rather than arbitrary API schemas.
- Delete verification is guarded and destructive tests remain disabled.
- Dashboard inventory endpoints are configurable contracts; the generated
  report is the currently available real data source.
- JWT refresh, OAuth providers, GraphQL, BOPLA, and BFLA are not implemented.
- The scanner cannot establish authorization when ownership or policy data is
  missing; it reports no confirmed vulnerability in that case.

Future work should add persistent scan models, a backend API for dashboard
inventory, disposable-resource lifecycle management, and broader integration
coverage before testing authorized non-lab targets.
