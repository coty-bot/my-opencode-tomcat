/**
 * End-to-end proof that taint crosses a reflective boundary in Tomcat.
 *
 * Path: OpenSSLCipherConfigurationParser.parse(String expression)  [SOURCE]
 *   -> parseInternal: elements = expression.split(...); elements[0]
 *   -> Class.forName("...OpenSSLLibrary").getMethod("findCiphers", String.class).invoke(null, elements[0])
 *   -> [reflection edge] OpenSSLLibrary.findCiphers(String) parameter  [SINK]
 */
import java
import semmle.code.java.dataflow.TaintTracking
import ReflectionCallGraph

module Config implements DataFlow::ConfigSig {
  // SOURCE: reads of the cipher-expression parameter of parse(String)
  predicate isSource(DataFlow::Node n) {
    exists(Method m |
      m.hasName("parse") and
      m.getDeclaringType().getQualifiedName() =
        "org.apache.tomcat.util.net.openssl.ciphers.OpenSSLCipherConfigurationParser" and
      n.asExpr() = m.getParameter(0).getAnAccess()
    )
  }

  // SINK: a read of a parameter of a reflectively-invoked method (taint reached into reflective code)
  predicate isSink(DataFlow::Node n) {
    exists(ReflectiveMethodInvoke inv, Method target, Parameter p |
      inv.argFlowsToParam(target, _, p) and n.asExpr() = p.getAnAccess()
    )
  }

  // CROSS the reflective boundary: invoke argument -> resolved target method parameter read
  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    exists(ReflectiveMethodInvoke inv, Method target, Expr arg, Parameter p |
      inv.argFlowsToParam(target, arg, p) and
      n1.asExpr() = arg and n2.asExpr() = p.getAnAccess()
    )
  }
}

module Flow = TaintTracking::Global<Config>;

from DataFlow::Node src, DataFlow::Node sink
where Config::isSource(src) and Config::isSink(sink) and Flow::flow(src, sink)
select
  src.asExpr().getLocation().getFile().getRelativePath() as sourceFile,
  src.asExpr().getLocation().getStartLine() as sourceLine,
  "taint crosses reflective invoke into",
  sink.asExpr().getLocation().getFile().getRelativePath() as sinkFile,
  sink.asExpr().getLocation().getStartLine() as sinkLine
