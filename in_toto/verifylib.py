"""
<Program Name>
  verifylib.py

<Author>
  Lukas Puehringer <lukas.puehringer@nyu.edu>

<Started>
  June 28, 2016

<Copyright>
  See LICENSE for licensing information.

<Purpose>

  Provides a library to verify a in_toto final product containing
  a software supply chain layout.

  The library provides functions to:
    - verify signatures of a layout
    - verify signatures of a link
    - verify if the expected command of a step aligns with the actual command
      as recorded in the link metadata file.
    - run inspections (records link metadata)
    - verify product or material matchrules for steps or inspections

"""

import sys
import datetime
import iso8601
import fnmatch
from dateutil import tz

import in_toto.util
import in_toto.runlib
import in_toto.models.layout
import in_toto.models.link
import in_toto.ssl_crypto.keys
from in_toto.exceptions import RuleVerficationFailed
from in_toto.matchrule_validators import check_matchrule_syntax
import in_toto.log as log


def run_all_inspections(layout):
  """
  <Purpose>
    Extracts all inspections from a passed Layout's inspect field and
    iteratively runs each inspections command as defined in the in Inspection's
    run field using in-toto runlib.  This producces link metadata which is
    returned as a dictionary with the according inspection names as keys and
    the Link metadata objects as values.

  <Arguments>
    layout:
            A Layout object which is used to extract the Inpsections.

  <Exceptions>
    TBA (see https://github.com/in-toto/in-toto/issues/6)

  <Side Effects>
    Executes the Inspection command and produces Link metadata.

  <Returns>
    A dictionary containing one Link metadata object per Inspection where
    the key is the Inspection name.
  """
  inspection_links_dict = {}
  for inspection in layout.inspect:
    # XXX LP: What should we record as material/product?
    # Is the current directory a sensible default? In general?
    # If so, we should propably make it a default in run_link
    # We could use matchrule paths
    link = in_toto.runlib.run_link(inspection.name, '.', '.',
        inspection.run.split())
    inspection_links_dict[inspection.name] = link
  return inspection_links_dict

def verify_layout_expiration(layout):
  """
  <Purpose>
    Raises an exception if the passed layout has expired, i.e. if its
    "expire" property is lesser "now".
    Time zone aware datetime objects in UTC+00:00 (Zulu Time) are used.

  <Arguments>
    layout:
            The Layout object to be verified.

  <Exceptions>
    LayoutExpiredError
    TBA (see https://github.com/in-toto/in-toto/issues/6)

  <Side Effects>
    None.

  """
  expire_datetime = iso8601.parse_date(layout.expires)
  if expire_datetime < datetime.datetime.now(tz.tzutc()):
    raise LayoutExpiredError("Layout expired")


def verify_layout_signatures(layout, keys_dict):
  """
  <Purpose>
    Iteratively verifies all signatures of a Layout object using the passed
    keys.

  <Arguments>
    layout:
            A Layout object whose signatures are verified.
    keys_dict:
            A dictionary of keys to verify the signatures conformant with
            ssl_crypto.formats.KEYDICT_SCHEMA.

  <Exceptions>
    Raises an exception if a needed key can not be found in the passed
    keys_dict or if a verification fails.
    TBA (see https://github.com/in-toto/in-toto/issues/6)

  <Side Effects>
    Verifies cryptographic Layout signatures.

  """
  layout.verify_signatures(keys_dict)


def verify_link_signatures(link, keys_dict):
  """
  <Purpose>
    Iteratively verifies all signatures of a Link object using the passed
    keys.

  <Arguments>
    link:
            A Link object whose signatures are verified.
    keys_dict:
            A dictionary of keys to verify the signatures conformant with
            ssl_crypto.formats.KEYDICT_SCHEMA.

  <Exceptions>
    Raises an exception if a needed key can not be found in the passed
    keys_dict or if a verification fails.
    TBA (see https://github.com/in-toto/in-toto/issues/6)

  <Side Effects>
    Verifies cryptographic Link signatures.

  """
  link.verify_signatures(keys_dict)


def verify_all_steps_signatures(layout, links_dict):
  """
  <Purpose>
    Extracts the Steps of a passed Layout and iteratively verifies the
    the signatures of the Link object related to each Step by the name field.
    The public keys used for verification are also extracted from the Layout.

  <Arguments>
    layout:
            A Layout object whose Steps are extracted and verified.
    links_dict:
            A dictionary of Link metadata objects with Link names as keys.

  <Exceptions>
    Raises an exception if a needed key can not be found in the passed
    keys_dict or if a verification fails.
    TBA (see https://github.com/in-toto/in-toto/issues/6)

  <Side Effects>
    Verifies cryptographic Link signatures related to Steps of a Layout.

  """
  for step in layout.steps:
    # Find the according link for this step
    link = links_dict[step.name]

    # Create the dictionary of keys for this step
    keys_dict = {}
    for keyid in step.pubkeys:
      keys_dict[keyid] = layout.keys[keyid]

    # Verify link metadata file's signatures
    verify_link_signatures(link, keys_dict)


def verify_command_alignment(command, expected_command):
  """
  <Purpose>
    Checks if a run command aligns with an expected command. The commands align
    if all of their elements are equal. If alignment fails, a warning is
    printed.

    Note:
      Command alignment is a weak guarantee. Because a functionary can easily
      alias commands.

  <Arguments>
    command:
            A command list, e.g. ["vi", "foo.py"]
    expected_command:
            A command list, e.g. ["make", "install"]

  <Exceptions>
    None.

  <Side Effects>
    Logs warning in case commands do not align.

  """
  # In what case command alignment should fail and how that failure should be
  # propagated has been thoughly discussed in:
  # https://github.com/in-toto/in-toto/issues/46 and
  # https://github.com/in-toto/in-toto/pull/47
  # We chose the simplest solution for now, i.e. Warn if they do not align.

  if command != expected_command:
    log.warning("Run command '{0}' differs from expected command '{1}'"
        .format(command, expected_command))


def verify_all_steps_command_alignment(layout, links_dict):
  """
  <Purpose>
    Iteratively checks if all expected commands as defined in the
    Steps of a Layout align with the actual commands as recorded in the Link
    metadata.

  <Arguments>
    layout:
            A Layout object to extract the expected commands from.
    links_dict:
            A dictionary of Link metadata objects with Link names as keys.

  <Exceptions>
    None.

  <Side Effects>
    None.

  """
  for step in layout.steps:
    # Find the according link for this step
    link = links_dict[step.name]
    command = link.command
    expected_command = step.expected_command.split()
    verify_command_alignment(command, expected_command)


def verify_match_rule(rule, artifact_queue, artifacts, links):
  """
  <Purpose>

    Matchrules link in-toto steps together. That is, they ensure that the
    specified artifacts were not modified outside of an in-toto step, neither
    their path or file name nor their content.

    Matchrules operate on two sets of artifacts, source artifacts and target
    artifacts.

    Source artifacts are materials or products, depending on whether the
    matchrule is listed in the material_matchrules or product_matrchules
    field of a Step or Inspection. They are reported by Link metadata that
    relates to the Step or Inspection that contains the rule.
    Furthermore, only artifacts that are in the artifact_queue, i.e. they have
    not been matched in a previous rule of this Step or Inspection are used.

    Target artifacts are materials or products, depending on the second keyword
    in the matchrule list. They are reported by the Link metadata that relates
    to the Step specified by the last argument of the rule.

  <Notes>
    Currently matchrule target can only be Steps on not Inspections. The
    reason for this is unclear. Therefor this is likely to change.

    Historical: Matchrules used to have an optional second path pattern
    parameter, to allow path and file renames outside of in-toto steps.
    This lead to problems, cf.
    https://github.com/in-toto/in-toto/issues/43#issuecomment-267472109


  <Arguments>
    rule:
            The rule to be verified. Format is one of:
            ["MATCH", "MATERIAL", "<path pattern>", "FROM", "<step name>"]
            ["MATCH", "PRODUCT", "<path pattern>", "FROM", "<step name>"]

    artifact_queue:
            A list of artifact paths that haven't been matched by a previous
            rule yet.

    artifacts:
            A dictionary of artifacts, depending on the list the rule was
            extracted from, materials or products of the step or inspection the
            rule was extracted from.
            The format is:
              {
                <path> : HASHDICTS
              }
            with artifact paths as keys and HASHDICTS as values.

    links:
            A dictionary of Link objects with Link names as keys.
            The Link objects relate to Steps.
            The contained materials and products are used as verification target.

  <Exceptions>
    raises FormatError if the rule does not conform with the rule format.
    raises an if a matchrule does not verify.
    TBA (see https://github.com/in-toto/in-toto/issues/6)

    RuleVerficationFailed if the source path is not in the source Link's
    artifacts, or the target link is not found, or the target path is not in
    the target link's artifacts or source path and target path hashes don't
    match.

  <Side Effects>
    Uses fnmatch.filter which translates a glob pattern to re.

  <Returns>
    The artifact queue minus the files that were matched by the rule.

  """
  check_matchrule_syntax(rule)

  path_pattern = rule[2]
  target_type = rule[1].lower()
  target_name = rule[-1]

  # Extract target artifacts from links
  if target_type == "material":
    target_artifacts = links[target_name].materials
  elif target_type == "product":
    target_artifacts = links[target_name].products

  filtered_source_artifacts = fnmatch.filter(artifacts.keys(),
      path_pattern)
  filtered_target_artifacts = fnmatch.filter(target_artifacts.keys(),
      path_pattern)

  # Filtered source artifacts that have not been matched by another rule
  #FIXME: We will probaly also need a target_artifact queue
  queued_source_artifacts = set(filtered_source_artifacts) & set(artifact_queue)

  source_artifacts_cnt = len(queued_source_artifacts)
  target_artifacts_cnt = len(filtered_target_artifacts)

  if source_artifacts_cnt != target_artifacts_cnt:
    raise RuleVerficationFailed("Rule {0} failed, path pattern '{1}' found "
      "{2} queued source artifacts and {3} target {4}s. Must be equal."
      .format(rule, path_pattern, source_artifacts_cnt, target_artifacts_cnt,
      target_type))


  # Test if each source artifact (path) that was filtered by the path pattern
  # and also appears in the artifact queue has an equivalent (by path and hash)
  # artifact in the target artifacts dictionary.

  # Note that below condition which checks if the source artifact is in the
  # target artifacts implicitly checks if the source artifact is also in the
  # list of filtered target artifacts, because the same path pattern was applied
  # on source and target.
  for path in queued_source_artifacts:
    # Check artifact paths
    if path not in target_artifacts:
      raise RuleVerficationFailed("Rule {0} failed, '{1}' not in target "
          "{2}s".format(rule, path, target_type))
    # If paths are good check artifact contents
    else:
      # FIXME: sha256 should not be hardcoded but be a setting instead
      hash_algo = "sha256"
      if artifacts[path][hash_algo] != target_artifacts[path][hash_algo]:
        raise RuleVerficationFailed("Rule {0} failed, hashes of '{1}' in source"
          " and target artifacts do not match. The artifact has changed"
          .format(rule, path, target_type))

  # All filtered source artifacts can be removed from the artifact list
  # if something was
  return list(set(artifact_queue) - set(queued_source_artifacts))


def verify_create_rule(rule, artifact_queue):
  """
  <Purpose>
    Verifies that path pattern - 2nd element of rule - matches at least one
    file in the artifact queue. This might conflict with common understanding of
    glob patterns (especially "*").

    The CREATE rule DOES NOT verify if the artifact has appeared in previous or
    will appear in later steps of the software supply chain.

  <Arguments>
    rule:
            The rule to be verified. Format is ["CREATE", "<path pattern>"]

    artifact_queue:
            A list of artifact paths that were not matched by a previous rule.

  <Exceptions>
    raises an FormatError if the rule does not conform with the rule format.
    TBA (see https://github.com/in-toto/in-toto/issues/6)

    RuleVerficationFailed if nothing is matched in the artifact queue.

  <Side Effects>
    Uses fnmatch.filter which translates a glob pattern to re.

  <Returns>
    The artifact queue minus the files that were matched by the rule.

  """
  check_matchrule_syntax(rule)
  path_pattern = rule[1]
  matched_artifacts = fnmatch.filter(artifact_queue, path_pattern)
  if not matched_artifacts:
    raise RuleVerficationFailed("Rule {0} failed, no artifacts were created"
        .format(rule))

  return list(set(artifact_queue) - set(matched_artifacts))


def verify_delete_rule(rule, artifact_queue):
  """
  <Purpose>
    Verifies that the path pattern - 2nd element of rule - does not match any
    files in the artifact queue.

    The DELETE rule DOES NOT verify if the artifact has appeared in previous or
    will appear in later steps of the software supply chain.

  <Arguments>
    rule:
            The rule to be verified. Format is ["DELETE", "<path pattern>"]

    artifact_queue:
            A list of artifact paths that were not matched by a previous rule.

  <Exceptions>
    raises FormatError if the rule does not conform with the rule format.
    TBA (see https://github.com/in-toto/in-toto/issues/6)

    RuleVerficationFailed if path pattern matches files in artifact queue.

  <Side Effects>
    Uses fnmatch.filter which translates a glob pattern to re.

  <Returns>
    None.
    In contrast to other rule types, the DELETE rule does not
    remove matched files from the artifact queue, because it MUST not match
    files in order to pass.

  """
  check_matchrule_syntax(rule)
  path_pattern = rule[1]
  matched_artifacts = fnmatch.filter(artifact_queue, path_pattern)
  if matched_artifacts:
    raise RuleVerficationFailed("Rule {0} failed, artifacts {1} "
        "were not deleted".format(rule, matched_artifacts))


def verify_item_rules(item_name, rules, artifacts, links):
  """
  <Purpose>
    Iteratively apply passed material or product matchrules to guarantee that
    all artifacts required by a rule are matched and that only artifacts
    required by a rule are matched.

  <Algorithm>
      1. Create an artifact queue (a list of all file names found in artifacts)
      2. For each rule
        a. Artifacts matched by a rule are removed from the artifact queue
           (see note below)
        b. If a rule cannot match the artifacts as specified by the rule
              raise an Exception
        c. If the artifacts queue is not empty after verification of a rule
              continue with the next rule and the updated artifacts queue
           If the artifacts queue is empty
              abort verification
      3. After processing all rules the artifact queue must be empty, if not
              raise an Exception

  <Note>
    Each rule will be applied on the artifacts currently in the queue, that is
    if artifacts were already matched by a previous rule in the list they
    cannot be matched again.

    This can lead to ambiguity in case of conflicting rules, e.g. given a step
    with a reported artifact "foo" and a rule list
    [["CREATE", "foo"], ["DELETE", "foo"]].
    In this case the verification would pass, because
    verify_create_rule would remove the artifact from the artifact queue, which
    would make "foo" appear as deleted for verify_delete_rule.

  <Arguments>
    item_name:
            The name of the item (Step or Inspection) being verified,
            used for user feedback.

    rules:
            The list of rules (material or product matchrules) for the item
            being verified.

    artifacts:
            The artifact dictionary (materials or products) as reported by the
            Link of the item being verified.

    links:
            A dictionary of Link objects with Link names as keys.
            The Link objects relate to Steps.
            The contained materials and products are used as verification target.


  <Exceptions>
    raises FormatError if a rule does not conform with the rule format.
    TBA (see https://github.com/in-toto/in-toto/issues/6)

  <Side Effects>
    None.

  """
  # A list of file paths, recorded as artifacts for this item
  artifact_queue = artifacts.keys()
  for rule in rules:
    check_matchrule_syntax(rule)
    if rule[0].lower() == "match":
      artifact_queue = verify_match_rule(rule, artifact_queue, artifacts, links)

    elif rule[0].lower() == "create":
      artifact_queue = verify_create_rule(rule, artifact_queue)

    elif rule[0].lower() == "delete":
      verify_delete_rule(rule, artifact_queue)

    # FIXME: MODIFY rule needs revision
    elif rule[0].lower() == "modify":
      raise Exception("modify rule is currently not implemented.")

    else:
      # FIXME: We should never get here since the rule format was verified before
      raise Exception("Invalid Matchrule", rule)

    if not artifact_queue:
      break

  if artifact_queue:
    raise RuleVerficationFailed("Artifacts {0} were not matched by any rule of "
        "item '{1}'".format(artifact_queue, item_name))


def verify_all_item_rules(items, links, target_links=None):
  """
  <Purpose>
    Iteratively verifies material matchrules and product matchrules of
    passed items (Steps or Inspections).

  <Arguments>
    items:
            A list containing Step or Inspection objects whose material
            and product matchrules will be verified.

    links:
            A dictionary of Link objects with Link names as keys. For each
            passed item (Step or Inspection) to be verified, the related Link
            object is taken from this list.

    target_links: (optional)
            A dictionary of Link objects with Link names as keys. Each Link
            object relates to one Step of the supply chain. The artifacts of
            these links are used as match targets for the the artifacts of the
            items to be verified.
            If omitted, the passed links are also used as target_links.

  <Exceptions>
    raises an Exception if a matchrule does not verify.
    TBA (see https://github.com/in-toto/in-toto/issues/6)

  <Side Effects>
    None.

  """
  if not target_links:
    target_links = links

  for item in items:
    link = links[item.name]
    verify_item_rules(item.name, item.material_matchrules,
        link.materials, target_links)
    verify_item_rules(item.name, item.product_matchrules,
        link.products, target_links)



