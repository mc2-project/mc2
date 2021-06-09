import mc2client as mc2
import mc2client.opaquesql as osql

# TODO: modify the `orchestrator` value in tests/config.yaml to reflect
# Opaque SQL driver IP address
mc2.set_config("config.yaml")
osql.run("opaquesql_example.scala")
