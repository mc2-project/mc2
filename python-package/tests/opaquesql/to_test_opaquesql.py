import opaqueclient as oc
import opaqueclient.opaquesql as osql

# TODO: modify the `orchestrator` value in tests/config.yaml to reflect
# Opaque SQL driver IP address
oc.set_config("config.yaml")
osql.run("opaquesql_example.scala")
