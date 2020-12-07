/**
 * @name Informed CVE-2020-14422
 * @id dtdm/14422/informed
 * @kind problem
 * @problem.severity warning
 */


import python
/* 
Checks to see if an assignment statement uses an IPv4Interface or
IPv6 Interface object as a key when creating a dictionary via literals.
*/
predicate is_unsafe_dict_literal(Dict d) {
  exists(Expr k |
    k = d.getAKey() and
    k.pointsTo().getClass().getName().matches("IPv_Interface"))
}

/*
Recurse subexpressions to find interface objects. Should hopefully allow more robust
analysis of set and dict comprehensions.
*/
predicate has_interface_object_recursive(Expr e) {
  e.getASubExpression().pointsTo().getClass().getName().matches("IPv_Interface") or
  has_interface_object_recursive(e.getASubExpression())
}

/*
Checks to see if the iterable in a dictionary comprehension has interface objects,
uses recursion to check all sub-expressions of the iterable. Is not sufficiently
robust yet.
*/
predicate is_unsafe_dict_comprehension(DictComp d) {
  has_interface_object_recursive(d.getIterable())
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

// Query generates any assignment statements that use IPv4 / IPv6 objects as keys for dicts
from Stmt s, AssignStmt a, Dict d, DictComp dc
where (s = a and is_unsafe_dict_setitem(a)) or
(s.getASubExpression() = d and is_unsafe_dict_literal(d)) or
(s.getASubExpression() = dc and is_unsafe_dict_comprehension(dc))
select s, "Unsafe use of IPv4 / IPv6 Interface object as dictionary key"

