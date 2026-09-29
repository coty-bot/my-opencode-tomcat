/**
 * Reflection-aware call graph for Tomcat security scanning.
 *
 * Adds edges across reflective invocations so that taint/dataflow can cross them:
 *   - java.lang.reflect.Method.invoke(obj, args...)  -> the inferred target Method
 *   - Constructor.newInstance(...) / Class.newInstance() -> the inferred constructed type
 *
 * Builds on semmle.code.java.Reflection (inferAccessedMethod / getInferredConstructedType),
 * which resolves targets that are statically knowable: literal forName("...") and
 * literal-name getMethod("name", ...). For dynamic targets, callers can additionally
 * over-approximate via getInvokedMethodExpr() + the receiver's static type.
 */
import java
import semmle.code.java.Reflection
import semmle.code.java.dataflow.DefUse
import semmle.code.java.dataflow.DataFlow

/** A reflective method invocation: `java.lang.reflect.Method.invoke(obj, args...)`. */
class ReflectiveMethodInvoke extends MethodCall {
  ReflectiveMethodInvoke() {
    this.getCallee().getDeclaringType().hasQualifiedName("java.lang.reflect", "Method") and
    this.getCallee().hasName("invoke")
  }

  /** The expression holding the `Method` object being invoked (the qualifier). */
  Expr getInvokedMethodExpr() { result = this.getQualifier() }

  /**
   * A method inferred to be the target of this reflective invocation. Resolves when the
   * Method object comes from a literal-name getMethod/getDeclaredMethod on an inferable class.
   */
  Method getATargetMethod() {
    exists(ReflectiveGetMethodCall gmc |
      // chained: getMethod(...).invoke(...) OR via a local variable (def-use)
      (this.getInvokedMethodExpr() = gmc or defUsePair(gmc, this.getInvokedMethodExpr()))
    | result = gmc.inferAccessedMethod() )
  }

  /**
   * Holds if argument expression `arg` of this invoke call corresponds to parameter `param`
   * of target method `target`. For Method.invoke(Object obj, Object... args): arg0 is the
   * instance; arg(i+1) maps to param i for individual varargs, or a single Object[] array
   * argument conservatively maps to every parameter.
   */
  predicate argFlowsToParam(Method target, Expr arg, Parameter param) {
    // Method.invoke(Object obj, Object... args): arg0 is the instance; arg(i+1) -> param i.
    exists(int i | 0 <= i and i < target.getNumberOfParameters() |
      target = this.getATargetMethod() and
      arg = this.getArgument(i + 1) and param = target.getParameter(i)
    )
  }

  /** All argument expressions of this invoke that flow into some parameter of a resolved target. */
  Expr getATaintedArgExpr(Method target) {
    exists(Parameter p | this.argFlowsToParam(target, result, p))
  }
}

/** A reflective constructor invocation: `Constructor.newInstance(...)` / `Class.newInstance()`. */
class ReflectiveNewInstance extends NewInstance {
  /** A type inferred to be constructed by this call. */
  RefType getATargetType() { result = this.getInferredConstructedType() }

  /** The Constructor inferred to be invoked by this call (when statically resolvable). */
  Constructor getATargetConstructor() { result = this.getInferredConstructor() }

  /**
   * Holds if argument expression `arg` of this newInstance call corresponds to parameter `param`
   * of target constructor `ctor`. For Constructor.newInstance(Object... args): arg(i) -> param i; a
   * single (var-args array) argument conservatively maps to every parameter.
   */
  predicate argFlowsToParam(Constructor ctor, Expr arg, Parameter param) {
    exists(int i | 0 <= i and i < ctor.getNumberOfParameters() |
      ctor = this.getATargetConstructor() and
      param = ctor.getParameter(i) and
      (arg = this.getArgument(i) or (this.getNumArgument() = 1 and arg = this.getArgument(0)))
    )
  }
}

/** A call to `java.lang.reflect.Proxy.newProxyInstance(loader, ifaces, handler)`. */
predicate isDynamicProxyCreation(MethodCall np) {
  np.getCallee().getDeclaringType().hasQualifiedName("java.lang.reflect", "Proxy") and
  np.getCallee().hasName("newProxyInstance")
}

/**
 * Holds if `mc` is a method call dispatched through a dynamic proxy created by `np`: the receiver of
 * `mc` is (intra-procedurally) the value returned by `np`. The dispatch lands in the handler's
 * InvocationHandler.invoke(proxy, method, args). Intra-procedural to stay tractable; cross-method
 * proxies are covered by manual review (Tomcat has only 3 newProxyInstance sites).
 */
predicate isDynamicProxyDispatch(MethodCall mc, MethodCall np) {
  isDynamicProxyCreation(np) and
  exists(DataFlow::Node n1, DataFlow::Node n2 |
    n1.asExpr() = np and n2.asExpr() = mc.getQualifier() and DataFlow::localFlow(n1, n2)
  )
}
