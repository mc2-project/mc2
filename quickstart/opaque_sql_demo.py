# This file performs the equivalent operations of opaque_sql_demo.scala, but in Python
# To use, replace run --> script in config.yaml with the path to this script
# and start --> head with the commands to start a PySpark cluster

# Load in the encrypted data
df = spark.read.format("edu.berkeley.cs.rise.opaque.EncryptedSource").load( # noqa: F821
    "/tmp/opaquesql.csv.enc"
)

# Filter out all patients older than 30
result = df.filter(df["Age"] < 30)

# This will save the result DataFrame to the result directory on the cloud
result.write.format("edu.berkeley.cs.rise.opaque.EncryptedSource").save(
    "/tmp/opaque_sql_result"
)
