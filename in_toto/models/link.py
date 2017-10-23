#!/usr/bin/env python
"""
<Program Name>
  link.py

<Author>
  Lukas Puehringer <lukas.puehringer@nyu.edu>
  Santiago Torres <santiago@nyu.edu>

<Started>
  Sep 23, 2016

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provides a class for link metadata which is information gathered when a
  step of the supply chain is performed.
"""

import attr
import json
import in_toto.models.common as models__common
import securesystemslib.formats
from in_toto.models.metadata import Metablock


FILENAME_FORMAT = "{step_name}.{keyid:.8}.link"
UNFINISHED_FILENAME_FORMAT = ".{step_name}.{keyid:.8}.link-unfinished"



class Link(Metablock):
  """
  A link is the metadata representation of a supply chain step performed
  by a functionary.

  Links are recorded, signed and stored to a file when a functionary wraps
  a command with in_toto-run.

  Links also contain materials and products which are hashes of the file before
  the command was executed and after the command was executed.

  <Attributes>
    signed: A LinkSignable object (described below)

    signatures: the signatures computed on the LinkSignable object

   """
  def __init__(self, **kwargs):
    # FIXME: this is a patch that will make code migration easier.
    if 'signed' not in kwargs:
      new_kwargs = {}
      new_kwargs['signed'] = {}
      new_kwargs['signed'].update(kwargs)
      kwargs = new_kwargs

    super(Link, self).__init__(**kwargs)


  def get_signable(self):
    """ This method is used by the base class's constructor to obtain the
     appropriate signable to populate itself. """
    return LinkSignable


  @staticmethod
  def read(data):
    """Static method to instantiate a new Link from a Python dictionary """
    return Link(**data)



@attr.s(repr=False, init=False)
class LinkSignable(models__common.Signable):
  """
  A link is the metadata representation of a supply chain step performed
  by a functionary.

  This object hold the *signable* part of a piece of link metadata. That is,
  the part from which the link's signature field will be computed.

  <Attributes>
    name:
        a unique name used to identify the related step in the layout

    materials and products:
        a dictionary in the format of
          { <relative file path> : {
            {<hash algorithm> : <hash of the file>}
          },... }

    byproducts:
        a dictionary in the format of
          {
            "stdout": <standard output of the executed command>,
            "stderr": <standard error of the executed command>,
            "return-value": the return value of the executed command
          }

    command:
        the command that was wrapped by in_toto-run

    return_value:
        the return value of the executed command

    environment:
        environment information, e.g.
        {
          "variables": <list of environment variable "KEY=value" pairs>,
          "filesystem": <filesystems info>,
          "workdir": <cwd while running `in-toto-run`>
        }

        Note: None of the values in environment is mandated
        runlib currently only records the workdir

  """
  _type = attr.ib()
  name = attr.ib()
  materials = attr.ib()
  products = attr.ib()
  byproducts = attr.ib()
  command = attr.ib()
  environment = attr.ib()



  def __init__(self, **kwargs):
    super(LinkSignable, self).__init__()

    self._type = "link"
    self.name = kwargs.get("name")
    self.materials = kwargs.get("materials", {})
    self.products = kwargs.get("products", {})
    self.byproducts = kwargs.get("byproducts", {})
    self.command = kwargs.get("command", [])
    self.environment = kwargs.get("environment", {})

    self.validate()


  def _validate_type(self):
    """Private method to check that `_type` is set to "link"."""
    if self._type != "link":
      raise securesystemslib.exceptions.FormatError(
          "Invalid Link: field `_type` must be set to 'link', got: {}"
          .format(self._type))


  def _validate_materials(self):
    """Private method to check that `materials` is a `dict` of `HASHDICTs`."""
    if not isinstance(self.materials, dict):
      raise securesystemslib.exceptions.FormatError(
          "Invalid Link: field `materials` must be of type dict, got: {}"
          .format(type(self.materials)))

    for material in self.materials.values():
      securesystemslib.formats.HASHDICT_SCHEMA.check_match(material)


  def _validate_products(self):
    """Private method to check that `products` is a `dict` of `HASHDICTs`."""
    if not isinstance(self.products, dict):
      raise securesystemslib.exceptions.FormatError(
          "Invalid Link: field `products` must be of type dict, got: {}"
          .format(type(self.products)))

    for product in self.products.values():
      securesystemslib.formats.HASHDICT_SCHEMA.check_match(product)


  def _validate_byproducts(self):
    """Private method to check that `byproducts` is a `dict`."""
    if not isinstance(self.byproducts, dict):
      raise securesystemslib.exceptions.FormatError(
          "Invalid Link: field `byproducts` must be of type dict, got: {}"
          .format(type(self.byproducts)))


  def _validate_command(self):
    """Private method to check that `command` is a `list`."""
    if not isinstance(self.command, list):
      raise securesystemslib.exceptions.FormatError(
          "Invalid Link: field `command` must be of type list, got: {}"
          .format(type(self.command)))


  def _validate_environment(self):
    """Private method to check that `environment` is a `dict`. """
    if not isinstance(self.environment, dict):
      raise securesystemslib.exceptions.FormatError(
          "Invalid Link: field `environment` must be of type dict, got: {}"
          .format(type(self.environment)))
