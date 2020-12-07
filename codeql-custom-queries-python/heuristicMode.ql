/**
 * @name Hueristic CVE-2020-14422
 * @id dtdm/14422/heuristic
 * @kind path-problem
 * @problem.severity warning
 */


import python
import semmle.python.security.TaintTracking
import semmle.python.web.HttpRequest


/* 
Checks to see if an assignment statement uses an IPv4Interface or
IPv6 Interface object as a key when creating a dictionary via literals.
*/
predicate is_unsafe_dict_literal(AssignStmt a) {
  exists(Dict d, Expr k |
    a.getASubExpression() = d and
    k = d.getAKey() and
    k.pointsTo().getClass().getName().matches("IPv_Interface"))
}

/*
Checks to see if an assignment statement adds an entry to a dictionary
using an IPv4Interface or IPv6Interface object as a key.
*/
predicate is_unsafe_dict_setitem(AssignStmt a) {
  exists (Value d, Value i |
    a.getTargets().getAnItem().getASubExpression().pointsTo() = d and
    a.getTargets().getAnItem().getASubExpression().pointsTo() = i and 
    i.getClass().getName().matches("IPv_Interface")  and
    d.getClass().getName().matches("%dict%"))
}

/*
Todo: Add additional predicates from safe mode. No sense doing
this until we fix the taint tracking program, but logic
will be identical.
*/
predicate is_unsafe_assignment(AssignStmt a) {
  is_unsafe_dict_literal(a) or is_unsafe_dict_setitem(a)
}

/*
Custom taint sink for targets of unsafe assignment statements
*/
class UnsafeSink extends TaintTracking::Sink {

  UnsafeSink() {
      exists(AssignStmt addtodict |
        addtodict.getATarget().getAFlowNode() = this and is_unsafe_assignment(addtodict)
      )
  }

  override predicate sinks(TaintKind kind) {
      kind instanceof StringKind
  }

}

/*
Custom sources for the heuristic method. Currently only checks http get requests
and file reads. Could add environment variables, etc. Any potential source
of user data
*/
class HeuristicSource extends TaintSource {
  HeuristicSource() {
    exists(FunctionValue f |
      f.getQualifiedName().matches("get") and
      f.getScope().getEnclosingModule().getName().matches("requests.api") and
      this = f.getAFunctionCall()
    ) or
    exists(PythonFunctionValue pf |
      pf.getQualifiedName().matches("%ile.read%") and
      this = pf.getAFunctionCall())
  }

  override string toString() { result = "Heuristic source" }

  override predicate isSourceOf(TaintKind kind) { kind instanceof StringKind }
}

/*
Modified taint tracking configuration taken from the semmle help files
*/
class HeuristicToUnsafeDictionaryConfig extends TaintTracking::Configuration {

  HeuristicToUnsafeDictionaryConfig() {
      this = "Example config finding flow from suspected source to unsafe dictionary update"
  }

  override predicate isSource(TaintTracking::Source src) { src instanceof HeuristicSource }

  override predicate isSink(TaintTracking::Sink sink) { sink instanceof UnsafeSink }

}



from HeuristicToUnsafeDictionaryConfig config, TaintTracking::Source src, TaintTracking::Sink sink
where config.hasFlow(src, sink)
select src, sink

