/**
 * @name Safe CVE-2020-14422
 * @id dtdm/14422/safe
 * @kind problem
 * @problem.severity warning
 */


/*
The original intention behind safe mode was that it would be a trivial query that simply checks
if the self.__hash__() function within our affected objects is reachable anywhere in the code base.
This turned out to be decidedly non-trivial, as the CodeQL AST for python doesn't extend into the
implementation of member operations.  E.g. The assignment statement node for the dict literal
assignment x = {SomeObject: 'value'} will not have child nodes for the call to dict.__setitem__()
or, accordingly, the subsequent calls to hash(SomeObject) used by the hashmap implementation.

In order to ensure we had as full coverage as possible we consulted the python3 datamodel reference,
which confirmss that object.__hash__(self) is only invoked by operations on hashed collections
(dict, set, frozenset) and by explicit calls to the built-in hash() function. Just to be safe
we analyzed the python standard libraries to make sure there no implicit calls to the built-in hash
function outside of private __hash__ declarations, and no direct accesses to private hash functions,
which would be a violation of the python design spec, but is technically possible. While we did
not find any direct accessess to private hash functions, we did actually find one instance of a
call to hash() on a non-self object within the standard libraries that was not a part of the
aformentioned list of hashed collections. It can be found in the HashedSeq function of the LRU Cache
decorator in functools.py. This is a decidedly niche case, so we decided to omit it from our
analysis.

Threat to validity: Our analysis of the standard libraries only included the python source. Much
of python is written in C, so there are some aspects of the code base we have yet to rule out
as potential entry points for internal calls to hash(). 
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

predicate is_unsafe_dict_comprehension(DictComp d) {
  // TODO: Is not sufficiently robust
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

/*
Checks to see if a Call is an instance of the built-in hash() function being called
on an interface object
*/
predicate is_unsound_hash(Call call) {
  exists (Name functionName, Name argumentName |
    call.getFunc() = functionName and functionName.getId().matches("hash") and
    argumentName = call.getAnArg() and
    argumentName.pointsTo().getClass().getName().matches("IPv_Interface")  )
}

/*
Checks to see if a Call adds an interface object to a set or frozen set
*/
predicate is_unsafe_set_add(Call c) {
  exists( Name n, Attribute a |
    c.getAnArg() = n and n.pointsTo().getClass().getName().matches("IPv_Interface") and
    c.getASubExpression() = a and ( a.getObject().pointsTo().getClass().getName().matches("set")
    or a.getObject().pointsTo().getClass().getName().matches("frozenset") ) )
}

/*
Checks to see if a set literal adds an interface object to a set
*/
predicate is_unsafe_set_literal(Set s) {
  exists (Name n |
    s.getAnElt() = n and n.pointsTo().getClass().getName().matches("IPv_Interface") )
}

/*
Checks to see if a set constructor is called on a list containing interface objects
TODO: Add support for additional iterables in the set constructor
*/
predicate is_unsafe_set_construction(Call c) {
  exists (Name n, List l |
    c.getFunc() = n and n.getId().matches("set") and
    c.getAnArg() = l and l.getAnElt().pointsTo().getClass().getName().matches("IPv_Interface"))
}

/*
Checks to see if a set comprehension creates a set containing interface objects.
Insufficiently robust but works on simple comprehensions
*/
predicate is_unsafe_set_comprehension(SetComp s) {
  has_interface_object_recursive(s.getIterable()) or
  exists (Call c|
  c.getFunc().pointsTo().getName().matches("%IPv_Interface%") and
  s.contains(c))
}

/*
Recurse subexpressions to find interface objects. Should hopefully allow more robust
analysis of set and dict comprehensions.
*/
predicate has_interface_object_recursive(Expr e) {
  e.getASubExpression().pointsTo().getClass().getName().matches("IPv_Interface") or
  has_interface_object_recursive(e.getASubExpression())
}


from Stmt s, AssignStmt a, Call c, SetComp sc, Set sl, Dict d, DictComp dc
where 
(s.getASubExpression() = c and (
  is_unsafe_set_construction(c) or is_unsafe_set_add(c) or is_unsound_hash(c))) or
(s.getASubExpression() = sc and is_unsafe_set_comprehension(sc)) or
(s.getASubExpression() = sl and is_unsafe_set_literal(sl)) or
(s.getASubExpression() = d and is_unsafe_dict_literal(d)) or
(s.getASubExpression() = dc and is_unsafe_dict_comprehension(dc)) or
(s = a and is_unsafe_dict_setitem(a))
select s, "found call to hash() on an interface object"
