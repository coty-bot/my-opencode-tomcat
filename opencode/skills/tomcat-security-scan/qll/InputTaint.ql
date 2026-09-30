/**
 * Client-HTTP-input TAINT SWEEP (general recon): report every dangerous sink in Tomcat whose
 * receiver or an argument is tainted from CLIENT HTTP input (Coyote/Catalina Request getters).
 *
 * Use as per-batch recon: set PKG to the package prefix under review ("" = whole codebase) and run.
 * It highlights hotspots for a worker to verify by hand — it is NOT a substitute for line-by-line
 * review (concurrency/state-machine/logic bugs are out of its reach). Best-effort on cross-method
 * taint; the manual pass is the backstop.
 *
 * Sink categories: deserialization, reflection, sql-exec, process/exec.
 */
import java
import semmle.code.java.dataflow.TaintTracking
import ReflectionCallGraph

predicate isClientReqType(string qn) {
  qn = "org.apache.coyote.Request" or
  qn = "org.apache.catalina.connector.RequestFacade" or
  qn = "org.apache.catalina.connector.Request"
}

predicate isClientInputMethod(string name) {
  name = "getMethod" or name = "getRequestURI" or name = "getQueryString" or
  name = "getHeader" or name = "getHeaders" or name = "getParameter" or
  name = "getParameterValues" or name = "getParameterMap" or name = "getCookies" or
  name = "getInputStream" or name = "getReader"
}

// --- sink predicates (each a MethodCall) ---
predicate isDeserSink(MethodCall mc) {
  (mc.getCallee().getDeclaringType().hasQualifiedName("java.io", "ObjectInputStream") and
   mc.getMethod().getName() = "readObject") or
  (mc.getCallee().getDeclaringType().hasQualifiedName("javax.xml", "XMLDecoder") and
   mc.getMethod().getName() = "readObject")
}

predicate isReflectSink(MethodCall mc) {
  (mc.getCallee().getDeclaringType().hasQualifiedName("java.lang.reflect", "Method") and
   mc.getMethod().getName() = "invoke") or
  (mc.getCallee().getDeclaringType().hasQualifiedName("java.lang", "Class") and
   mc.getMethod().getName() = "forName") or
  isDynamicProxyCreation(mc)
}

predicate isSqlSink(MethodCall mc) {
  mc.getCallee().getDeclaringType().getPackage().getName().matches("java.sql%") and
  (mc.getMethod().getName() = "execute" or mc.getMethod().getName() = "executeQuery" or
   mc.getMethod().getName() = "executeUpdate" or mc.getMethod().getName() = "addBatch")
}

predicate isExecSink(MethodCall mc) {
  (mc.getCallee().getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
   mc.getMethod().getName() = "exec") or
  (mc.getCallee().getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
   mc.getMethod().getName() = "start")
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) {
    exists(MethodCall mc |
      n.asExpr() = mc and
      isClientReqType(mc.getQualifier().getType().(RefType).getQualifiedName()) and
      isClientInputMethod(mc.getMethod().getName())
    )
  }

  // Every node is a sink so taint propagates everywhere; we filter to our sinks in the query.
  predicate isSink(DataFlow::Node n) { any() }
}

module Flow = TaintTracking::Global<Config>;

// Does client-input taint reach expression e?
predicate clientTainted(Expr e) {
  exists(DataFlow::Node a, DataFlow::Node s | a.asExpr() = e and Config::isSource(s) and Flow::flow(s, a))
}

// A dangerous sink whose receiver or some argument is client-tainted.
predicate callHasClientInput(MethodCall mc) {
  (exists(Expr q | q = mc.getQualifier() and clientTainted(q))) or
  exists(int i | 0 <= i and i < mc.getNumArgument() and clientTainted(mc.getArgument(i)))
}

// Scope filter: edit this path prefix per batch (e.g. "org/apache/catalina/session%"). Use "%" alone for whole codebase.
predicate inScope(File f) { f.getRelativePath().matches("org/apache/catalina/webresources%") }

from string category, MethodCall site
where
  ((category = "deserialization" and isDeserSink(site)) or
   (category = "reflection" and isReflectSink(site)) or
   (category = "sql-exec" and isSqlSink(site)) or
   (category = "process/exec" and isExecSink(site))) and
  callHasClientInput(site) and inScope(site.getLocation().getFile())
select category, site.getLocation().getFile().getRelativePath() as file,
  site.getLocation().getStartLine() as line,
  site.getCallee().getDeclaringType().getQualifiedName() + "." + site.getMethod().getName() as sink
