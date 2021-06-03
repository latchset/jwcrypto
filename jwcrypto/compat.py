# Copyright (C) 2021 JWCrypto Project Contributors - see LICENSE file

from __future__ import absolute_import

import sys

PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] == 3


if PY3:
    string_types = (str, )

    def iteritems(d, **kw):
        return iter(d.items(**kw))

else:
    string_types = (basestring, )  # noqa: F821

    def iteritems(d, **kw):
        return d.iteritems(**kw)


def add_metaclass(metaclass):
    """Class decorator for creating a class with a metaclass."""
    def wrapper(cls):
        orig_vars = cls.__dict__.copy()
        slots = orig_vars.get('__slots__')
        if slots is not None:
            if isinstance(slots, str):
                slots = [slots]
            for slots_var in slots:
                orig_vars.pop(slots_var)
        orig_vars.pop('__dict__', None)
        orig_vars.pop('__weakref__', None)
        if hasattr(cls, '__qualname__'):
            orig_vars['__qualname__'] = cls.__qualname__
        return metaclass(cls.__name__, cls.__bases__, orig_vars)
    return wrapper
