import edu.berkeley.cs.rise.opaque.implicits._
edu.berkeley.cs.rise.opaque.Utils.initSQLContext(spark.sqlContext)

val data = Seq(("foo", 4), ("bar", 1), ("baz", 5))
val df = spark.createDataFrame(data).toDF("word", "count")
val dfEncrypted = df.encrypted
val result = dfEncrypted.filter($"count" > lit(3))
// This will save the result DataFrame to the result directory locally
result.write.format("edu.berkeley.cs.rise.opaque.EncryptedSource").save("result")


