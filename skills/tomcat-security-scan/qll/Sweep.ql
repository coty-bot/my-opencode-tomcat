/**
 * Broadened reflection-taint SWEEP: report every reflective boundary in Tomcat whose argument is
 * tainted from CLIENT HTTP input, across THREE channels:
 *   1. method-invoke     : java.lang.reflect.Method.invoke(obj, args...)
 *   2. ctor-newinstance  : Constructor.newInstance(args...) / Class.newInstance()
 *   3. proxy-dispatch    : a method call dispatched through a dynamic Proxy (-> InvocationHandler)
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

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) {
    exists(MethodCall mc |
      n.asExpr() = mc and
      isClientReqType(mc.getQualifier().getType().(RefType).getQualifiedName()) and
      isClientInputMethod(mc.getMethod().getName())
    )
  }

  predicate isSink(DataFlow::Node n) { any() }
}

module Flow = TaintTracking::Global<Config>;

// Does client-input taint reach expression e?
predicate clientTainted(Expr e) {
  exists(DataFlow::Node a, DataFlow::Node s | a.asExpr() = e and Config::isSource(s) and Flow::flow(s, a))
}

from string channel, Expr site, int argIndex
where
  (
    // Channel 1: Method.invoke with a client-tainted argument
    exists(ReflectiveMethodInvoke inv |
      0 <= argIndex and argIndex < inv.getNumArgument() and clientTainted(inv.getArgument(argIndex)) |
      channel = "method-invoke" and site = inv)
    or
    // Channel 2: Constructor.newInstance with a client-tainted argument
    exists(ReflectiveNewInstance ni |
      0 <= argIndex and argIndex < ni.getNumArgument() and clientTainted(ni.getArgument(argIndex)) |
      channel = "ctor-newinstance" and site = ni)
    or
    // Channel 3: method call dispatched through a dynamic proxy with a client-tainted argument
    exists(MethodCall mc, MethodCall np |
      isDynamicProxyDispatch(mc, np) and
      0 <= argIndex and argIndex < mc.getNumArgument() and clientTainted(mc.getArgument(argIndex)) |
      channel = "proxy-dispatch" and site = mc)
  )
select
  channel,
  site.getLocation().getFile().getRelativePath() as file,
  site.getLocation().getStartLine() as line,
  argIndex
