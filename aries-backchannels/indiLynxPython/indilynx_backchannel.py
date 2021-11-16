import asyncio
import json
import logging
import os
import uuid

from typing import Tuple

from aiohttp import (
    web,
    ClientRequest,
)

from python.agent_backchannel import (
    AgentBackchannel,
    RUN_MODE,
)
from python.utils import log_msg, prompt_loop
from python.storage import (
    get_resource,
    push_resource,
    pop_resource,
    pop_resource_latest,
)
import sirius_sdk
from sirius_sdk.messaging import restore_message_instance
from helpers import get_agent_params

from enum import Enum

LOGGER = logging.getLogger(__name__)

MAX_TIMEOUT = 5

AGENT_NAME = os.getenv("AGENT_NAME", "Agent")

# AIP level is 10 or 20
AIP_CONFIG = int(os.getenv("AIP_CONFIG", "10"))

# backchannel-specific args
EXTRA_ARGS = os.getenv("EXTRA_ARGS")

# other configs ...
DEFAULT_BIN_PATH = "../venv/bin"
DEFAULT_PYTHON_PATH = ".."

if RUN_MODE == "docker":
    DEFAULT_BIN_PATH = "./bin"
    DEFAULT_PYTHON_PATH = "."
elif RUN_MODE == "pwd":
    DEFAULT_BIN_PATH = "./bin"
    DEFAULT_PYTHON_PATH = "."


class Logger:

    async def __call__(self, *args, **kwargs):
        log_msg(str(dict(**kwargs)))


class IndiLynxConnection:

    class State(Enum):
        invited = 0,
        requested = 1,
        responded = 2,
        complete = 3

    def __init__(self, connection_id: str, invitation: sirius_sdk.aries_rfc.Invitation = None):
        self.connection_id = connection_id
        self.state = IndiLynxConnection.State.invited
        self.invitation = invitation
        self.pairwise = None

    def to_json(self):
        return json.dumps({
            "connection_id": self.connection_id,
            "state": self.state.name
        })


class IndiLynxIssuing:

    def __init__(self, connection_id: str, credential_id: str=None):
        self.connection_id = connection_id
        self.credential_id = credential_id
        self.proposal = None


class IndiLynxCloudAgentBackchannel(AgentBackchannel):

    def __init__(
        self,
        ident: str,
        http_port: int,
        admin_port: int,
        genesis_data: str = None,
        params: dict = {},
        extra_args: dict = {},
    ):
        super().__init__(ident, http_port, admin_port, genesis_data, params, extra_args)

        # set the auto response/request flags
        self.auto_accept_requests = False
        self.auto_respond_messages = False
        self.auto_respond_credential_proposal = False
        self.auto_respond_credential_offer = False
        self.auto_respond_credential_request = False
        self.auto_respond_presentation_proposal = False
        self.auto_respond_presentation_request = False

        self.connections = dict()
        self.issuing = dict()
        self.dkms_name = "default"
        self.master_secret_id = "master_secret_id"

    async def start_listener(self):
        listener = await sirius_sdk.subscribe()
        print("Listening")
        async for event in listener:
            request = event['message']
            if isinstance(request, sirius_sdk.aries_rfc.ConnRequest):
                log_msg("received: " + str(request))
                my_did, my_verkey = await sirius_sdk.DID.create_and_store_my_did()
                me = sirius_sdk.Pairwise.Me(did=my_did, verkey=my_verkey)
                connection_key = event['recipient_verkey']
                my_endpoint = [e for e in await sirius_sdk.endpoints() if e.routing_keys == []][0]
                inviter_machine = sirius_sdk.aries_rfc.Inviter(
                    me=me,
                    connection_key=connection_key,
                    my_endpoint=my_endpoint,
                    logger=Logger()
                )
                ok, pairwise = await inviter_machine.create_connection(request)
                if ok:
                    await sirius_sdk.PairwiseList.ensure_exists(pairwise)
                    self.connections[connection_key].pairwise = pairwise
                    self.connections[connection_key].state = IndiLynxConnection.State.complete
            elif isinstance(request, sirius_sdk.aries_rfc.OfferCredentialMessage):
                log_msg("received: " + str(request))
                offer: sirius_sdk.aries_rfc.OfferCredentialMessage = request
                pairwise = event.pairwise
                holder_machine = sirius_sdk.aries_rfc.Holder(
                    pairwise=pairwise,
                    logger=Logger()
                )
                success, cred_id = await holder_machine.accept(
                    offer=offer,
                    master_secret_id=self.master_secret_id
                )
            elif isinstance(request, sirius_sdk.aries_rfc.ProposeCredentialMessage):
                proposal: sirius_sdk.aries_rfc.ProposeCredentialMessage = request
                pairwise = event.pairwise
                conn_id = None
                for conn_id in self.connections:
                    conn = self.connections[conn_id]
                    if conn.pairwise and conn.pairwise.their.did == pairwise.their.did:
                        conn_id = conn.connection_id
                if conn_id:
                    self.issuing[conn_id] = IndiLynxIssuing(connection_id=conn_id, credential_id=conn_id)
                    self.issuing[conn_id].proposal = proposal

    async def swap_thread_id_for_exchange_id(self, thread_id, data_type, id_txt):
        timeout = 0
        webcall_returned = None
        while webcall_returned is None or timeout == 20:
            msg = get_resource(thread_id, data_type)
            try:
                ex_id = msg[0][id_txt]
                webcall_returned = True
            except TypeError:
                await asyncio.sleep(1)
                timeout += 1
        if timeout == 20:
            raise TimeoutError(
                "Timeout waiting for web callback to retrieve the thread id based on the exchange id"
            )
        return ex_id

    async def expected_agent_state(self, path, status_txt, wait_time=2.0, sleep_time=0.5):
        await asyncio.sleep(sleep_time)
        state = "None"
        if type(status_txt) != list:
            status_txt = [status_txt]
        for i in range(int(wait_time/sleep_time)):
            (resp_status, resp_text) = await self.make_admin_request("GET", path)
            if resp_status == 200:
                resp_json = json.loads(resp_text)
                state = resp_json["state"]
                if state in status_txt:
                    return True
            await asyncio.sleep(sleep_time)
        print("Expected state", status_txt, "but received", state, ", with a response status of", resp_status)
        return False

    async def make_agent_POST_request(
        self, op, rec_id=None, data=None, text=False, params=None
    ) -> Tuple[int, str]:

        if op["topic"] == "connection":
            operation = op["operation"]
            if operation == "create-invitation":
                connection_key = await sirius_sdk.Crypto.create_key()
                inviter_endpoint = [e for e in await sirius_sdk.endpoints() if e.routing_keys == []][0]
                invitation = sirius_sdk.aries_rfc.Invitation(
                    label='IndiLynx Agent',
                    endpoint=inviter_endpoint.address,
                    recipient_keys=[connection_key]
                )
                self.connections[connection_key] = IndiLynxConnection(connection_id=connection_key, invitation=invitation)
                return 200, json.dumps({
                    "connection_id": connection_key,
                    "invitation": invitation
                })

            elif operation == "receive-invitation":
                invitation = sirius_sdk.aries_rfc.Invitation(**dict(data))
                log_msg("received: " + str(invitation))
                invitation.validate()
                connection_id = str(uuid.uuid1())
                self.connections[connection_id] = IndiLynxConnection(connection_id=connection_id, invitation=invitation)
                return 200, json.dumps({
                    "connection_id": connection_id,
                    "state": "invitation"
                })

            elif operation == "accept-invitation":
                connection_id = rec_id
                invitation = self.connections[connection_id].invitation
                did, verkey = await sirius_sdk.DID.create_and_store_my_did()
                me = sirius_sdk.Pairwise.Me(did, verkey)
                my_endpoint = [e for e in await sirius_sdk.endpoints() if e.routing_keys == []][0]
                invitee = sirius_sdk.aries_rfc.Invitee(
                    me=me,
                    my_endpoint=my_endpoint,
                    logger=Logger()
                )
                ok, pairwise = await invitee.create_connection(invitation=invitation, my_label='IndiLynx Invitee')
                if ok:
                    self.connections[connection_id].pairwise = pairwise
                    self.connections[connection_id].state = IndiLynxConnection.State.complete
                    return 200, json.dumps({
                        "connection_id": connection_id,
                        "state": "active"
                    })
                else:
                    return 500, str(invitee.problem_report)
            elif operation == "accept-request":
                return 200, ""
            elif operation == "send-ping":
                connection_id = rec_id
                await asyncio.sleep(1)
                return 200, json.dumps({
                    "connection_id": connection_id,
                    "state": "active"
                })

        elif op["topic"] == "schema":
            json_data = json.loads(data)
            schema_name = json_data["schema_name"]
            schema_version = json_data["schema_version"]
            attributes = json_data["attributes"]
            schema_id, anoncred_schema = await sirius_sdk.AnonCreds.issuer_create_schema(issuer_did=self.did,
                                                            name=schema_name,
                                                            version=schema_version,
                                                            attrs=attributes)
            return 200, json.dumps({
                "schema_id": schema_id,
                "schema": anoncred_schema
            })

        elif op["topic"] == "credential-definition":
            json_data = json.loads(data)
            support_revocation = json_data["support_revocation"]
            schema_id = json_data["schema_id"]
            tag = json_data["tag"]

            return 500, "Not implemented"

        elif op["topic"] == "issue-credential":
            operation = op["operation"]
            if operation == "send-proposal":
                json_data = json.loads(data)
                connection_id = json_data["connection_id"]
                if connection_id in self.connections:
                    if self.connections[connection_id].state == IndiLynxConnection.State.complete:
                        pw: sirius_sdk.Pairwise = self.connections[connection_id].pairwise
                        proposed_attribs = []
                        for attr in json_data["credential_proposal"]["attributes"]:
                            proposed_attribs += sirius_sdk.aries_rfc.ProposedAttrib(attr["name"], attr["value"])
                        proposal = sirius_sdk.aries_rfc.ProposeCredentialMessage(
                            comment=json_data["comment"],
                            proposal_attrib=proposed_attribs,
                            schema_id=json_data["schema_id"],
                            schema_name=json_data["schema_name"],
                            schema_version=json_data["schema_version"],
                            schema_issuer_did=json_data["schema_issuer_did"],
                            cred_def_id=json_data["cred_def_id"],
                            issuer_did=json_data["issuer_did"]
                        )
                        await sirius_sdk.send_to(proposal, pw)
                        credential_id = proposal.id
                        self.issuing[connection_id] = IndiLynxIssuing(
                            connection_id=connection_id,
                            credential_id=credential_id
                        )
                        self.issuing[connection_id].proposal = proposal
                        return 200, json.dumps({
                                "state": "proposal-sent",
                                "thread_id": proposal.id,
                                "credential_id": credential_id
                        })
                    else:
                        log_msg("Connection is not complete")
                else:
                    log_msg("Connection id does not exist")

            elif operation == "send-offer":
                json_data = json.loads(data)
                connection_id = json_data["connection_id"]
                pw: sirius_sdk.Pairwise = self.connections[connection_id].pairwise
                issuer_machine = sirius_sdk.aries_rfc.Issuer(holder=pw)
                values = {}
                for attr in json_data["credential_preview"]["attributes"]:
                    values[attr["name"]] = attr["value"]
                proposal: sirius_sdk.aries_rfc.ProposeCredentialMessage = self.issuing[connection_id].proposal

                dkms = await sirius_sdk.ledger(self.dkms_name)
                schema = await dkms.load_schema(proposal.schema_id, self.did)
                cred_def = await dkms.load_cred_def(proposal.cred_def_id, self.did)
                credential_id = self.issuing[connection_id].credential_id
                ok = await issuer_machine.issue(
                    values=values,
                    comment=json_data["comment"],
                    schema=schema,
                    cred_def=cred_def,
                    cred_id=credential_id
                )
                if ok:
                    return 200, json.dumps({
                        "state": "credential-issued",
                        "thread_id": proposal.id,
                        "credential_id": credential_id
                    })
                else:
                    return 500, str(issuer_machine.problem_report)

    async def handle_out_of_band_POST(self, op, rec_id=None, data=None):
        operation = op["operation"]
        agent_operation = "/out-of-band/"
        log_msg(
            f"Data passed to backchannel by test for operation: {agent_operation}", data
        )
        if operation == "send-invitation-message":
            # http://localhost:8022/out-of-band/create-invitation?auto_accept=false&multi_use=false
            # TODO Check the data for auto_accept and multi_use. If it exists use those values then pop them out, otherwise false.
            auto_accept = "false"
            multi_use = "false"
            agent_operation = (
                agent_operation
                + "create-invitation"
                + "?multi_use="
                + multi_use
            )

            # Add handshake protocols to message body
            admindata = {
                "handshake_protocols": [
                    "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0"
                ],
                "use_public_did": data["use_public_did"],
            }
            data = admindata

        elif operation == "receive-invitation":
            # TODO check for Alias and Auto_accept in data to add to the call (works without for now)
            if "use_existing_connection" in data:
                use_existing_connection = str(data["use_existing_connection"]).lower()
                data.pop("use_existing_connection")
            else:
                use_existing_connection = "false"
            auto_accept = "false"
            agent_operation = (
                agent_operation
                + "receive-invitation"
                + "?use_existing_connection="
                + use_existing_connection
            )
            # agent_operation = "/didexchange/" + "receive-invitation"

        log_msg(
            f"Data translated by backchannel to send to agent for operation: {agent_operation}",
            data,
        )

        (resp_status, resp_text) = await self.admin_POST(agent_operation, data)
        log_msg(resp_status, resp_text)
        if resp_status == 200:
            resp_text = self.agent_state_translation(op["topic"], operation, resp_text)
        return (resp_status, resp_text)

    async def handle_did_exchange_POST(self, op, rec_id=None, data=None):
        operation = op["operation"]
        agent_operation = "/didexchange/"
        if operation == "send-request":
            agent_operation = agent_operation + rec_id + "/accept-invitation"

        elif operation == "receive-invitation":
            agent_operation = agent_operation + operation

        elif operation == "send-response":
            if self.auto_accept_requests:
                resp_status = 200
                resp_text = 'Aca-py agent in auto accept request mode. accept-request operation not called.'
                return (resp_status, resp_text)
            else:
                agent_operation = agent_operation + rec_id + "/accept-request"
                await asyncio.sleep(1)

        elif operation == "create-request-resolvable-did":
            their_public_did = data["their_public_did"]
            agent_operation = (
                agent_operation + "create-request?their_public_did=" + their_public_did
            )
            data = None

        elif operation == "receive-request-resolvable-did":
            # as of PR 1182 in aries-cloudagent-python receive-request is no longer needed.
            # this is done automatically by the responder.
            # The test expects a connection_id returned so, return the last webhook message
            # agent_operation = agent_operation + "receive-request"

            (wh_status, wh_text) = await self.make_agent_GET_request_response(
                op["topic"], rec_id=None, message_name="didexchange-msg"
            )
            return (wh_status, wh_text)

        (resp_status, resp_text) = await self.admin_POST(agent_operation, data)
        if resp_status == 200:
            resp_text = self.agent_state_translation(op["topic"], operation, resp_text)
        return (resp_status, resp_text)

    async def handle_issue_credential_v2_POST(self, op, rec_id=None, data=None):
        operation = op["operation"]
        topic = op["topic"]

        if self.auto_respond_credential_proposal and operation == "send-offer" and rec_id:
            resp_status = 200
            resp_text = '{"message": "Aca-py agent in auto respond mode for proposal. send-offer operation not called."}'
            return (resp_status, resp_text)
        elif self.auto_respond_credential_offer and operation == "send-request":
            resp_status = 200
            resp_text = '{"message": "Aca-py agent in auto respond mode for offer. send-request operation not called."}'
            return (resp_status, resp_text)
        elif self.auto_respond_credential_request and operation == "issue":
            resp_status = 200
            resp_text = '{"message": "Aca-py agent in auto respond mode for request. issue operation not called."}'
            return (resp_status, resp_text)
        else:

            if operation == "prepare-json-ld":
                key_type = self.proofTypeKeyTypeTranslationDict[data["proof_type"]]

                # Retrieve matching dids
                resp_status, resp_text = await self.admin_GET(
                    "/wallet/did",
                    params={"method": data["did_method"], "key_type": key_type},
                )

                did = None
                if resp_status == 200:
                    resp_json = json.loads(resp_text)

                    # If there is a matching did use it
                    if len(resp_json["results"]) > 0:
                        # Get first matching did
                        did = resp_json["results"][0]["did"]

                # If there was no matching did create a new one
                if not did:
                    (resp_status, resp_text) = await self.admin_POST(
                        "/wallet/did/create",
                        {"method": data["did_method"], "options": {"key_type": key_type}},
                    )
                    if resp_status == 200:
                        resp_json = json.loads(resp_text)
                        did = resp_json["result"]["did"]

                if did:
                    resp_text = json.dumps({"did": did})

                log_msg(resp_status, resp_text)
                return (resp_status, resp_text)

            if rec_id is None:
                agent_operation = (
                    self.TopicTranslationDict[topic]
                    + self.issueCredentialv2OperationTranslationDict[operation]
                )
            else:
                # swap thread id for cred ex id from the webhook
                cred_ex_id = await self.swap_thread_id_for_exchange_id(
                    rec_id, "credential-msg", "cred_ex_id"
                )
                agent_operation = (
                    self.TopicTranslationDict[topic]
                    + "records/"
                    + cred_ex_id
                    + "/"
                    + self.issueCredentialv2OperationTranslationDict[operation]
                )

            # Map AATH filter keys to ACA-Py filter keys
            # e.g. data.filters.json-ld becomes data.filters.ld_proof
            if data and "filter" in data:
                data["filter"] = dict(
                    (self.credFormatFilterTranslationDict[name], val)
                    for name, val in data["filter"].items()
                )

            log_msg(agent_operation, data)
            await asyncio.sleep(1)
            (resp_status, resp_text) = await self.admin_POST(agent_operation, data)

            if operation == "store":
                resp_json = json.loads(resp_text)

                if resp_json["ld_proof"]:
                    resp_json["json-ld"] = resp_json.pop("ld_proof")

                # Return less ACA-Py specific credential identifier key
                for key in resp_json:
                    if resp_json[key] and resp_json[key].get("cred_id_stored"):
                        resp_json[key]["credential_id"] = resp_json[key].get(
                            "cred_id_stored"
                        )

                resp_text = json.dumps(resp_json)

            log_msg(resp_status, resp_text)
            # Looks like all v2 states are RFC states. Yah!
            # if resp_status == 200: resp_text = self.agent_state_translation(topic], None, resp_text)
            resp_text = self.move_field_to_top_level(resp_text, "state")
            return (resp_status, resp_text)

    async def make_agent_GET_request(
        self, op, rec_id=None, text=False, params=None
    ) -> Tuple[int, str]:

        if op["topic"] == "status":
            status = 200 if self.ACTIVE else 418
            status_msg = "Active" if self.ACTIVE else "Inactive"
            return status, json.dumps({"status": status_msg})

        if op["topic"] == "version":
            return 200, "1.0"

        elif op["topic"] == "connection":
            if rec_id:
                connection_id = rec_id
                if connection_id in self.connections:
                    return 200, self.connections[connection_id].to_json()
                else:
                    return 500, rec_id + " not recognized"
            else:
                res = []
                for connection_id in self.connections:
                    res.append(self.connections[connection_id].to_json)

                return 200, str(res)

        elif op["topic"] == "did":
            return 500, "Not implemented"

        elif op["topic"] == "active-connection" and rec_id:
            agent_operation = f"/connections?their_did={rec_id}"

            (resp_status, resp_text) = await self.admin_GET(agent_operation)
            if resp_status != 200:
                return (resp_status, resp_text)

            # find the first active connection 
            resp_json = json.loads(resp_text)
            for connection in resp_json["results"]:
                if connection["state"] == "active":
                    resp_text = json.dumps(connection)
                    return (resp_status, resp_text)

            return (400, f"Active connection not found for their_did {rec_id}")

        elif op["topic"] == "schema":
            schema_id = rec_id
            dkms = await sirius_sdk.ledger(self.dkms_name)
            schema = await dkms.load_schema(schema_id, self.public_did)
            return 200, json.dumps(schema)

        elif op["topic"] == "credential-definition":
            cred_def_id = rec_id
            dkms = await sirius_sdk.ledger(self.dkms_name)
            cred_defs = await dkms.fetch_cred_defs(id_=cred_def_id)
            return 200, json.dumps(cred_defs)

        elif op["topic"] == "issue-credential":
            # swap thread id for cred ex id from the webhook
            cred_ex_id = await self.swap_thread_id_for_exchange_id(
                rec_id, "credential-msg", "credential_exchange_id"
            )
            agent_operation = (
                self.TopicTranslationDict[op["topic"]] + "records/" + cred_ex_id
            )

            (resp_status, resp_text) = await self.admin_GET(agent_operation)
            if resp_status == 200:
                resp_text = self.agent_state_translation(op["topic"], None, resp_text)
            return (resp_status, resp_text)

        elif op["topic"] == "issue-credential-v2":
            # swap thread id for cred ex id from the webhook
            cred_ex_id = await self.swap_thread_id_for_exchange_id(
                rec_id, "credential-msg", "cred_ex_id"
            )
            agent_operation = (
                self.TopicTranslationDict[op["topic"]] + "records/" + cred_ex_id
            )

            (resp_status, resp_text) = await self.admin_GET(agent_operation)
            resp_text = self.move_field_to_top_level(resp_text, "state")
            return (resp_status, resp_text)

        elif op["topic"] == "credential":
            operation = op["operation"]
            if operation == "revoked":
                agent_operation = "/credential/" + operation + "/" + rec_id
                (resp_status, resp_text) = await self.admin_GET(agent_operation)
                return (resp_status, resp_text)
            else:
                # NOTE: We don't know what type of credential to fetch, so we first try an indy credential.
                # Maybe it would be nice if the test harness passed the credential format that belonged to the
                # credential
                # First try indy credential
                agent_operation = "/credential/" + rec_id
                (resp_status, resp_text) = await self.admin_GET(agent_operation)

                # If not found try w3c credential
                if resp_status == 404:
                    agent_operation = "/credential/w3c/" + rec_id
                    (resp_status, resp_text) = await self.admin_GET(agent_operation)

                    if resp_status == 200:
                        resp_json = json.loads(resp_text)
                        return (
                            resp_status,
                            json.dumps(
                                {
                                    "credential_id": resp_json["record_id"],
                                    "credential": resp_json["cred_value"],
                                }
                            ),
                        )

                return (resp_status, resp_text)

        elif op["topic"] == "proof":
            # swap thread id for pres ex id from the webhook
            pres_ex_id = await self.swap_thread_id_for_exchange_id(
                rec_id, "presentation-msg", "presentation_exchange_id"
            )
            agent_operation = "/present-proof/records/" + pres_ex_id

            (resp_status, resp_text) = await self.admin_GET(agent_operation)
            if resp_status == 200:
                resp_text = self.agent_state_translation(op["topic"], None, resp_text)
            return (resp_status, resp_text)

        elif op["topic"] == "proof-v2":
            # swap thread id for pres ex id from the webhook
            pres_ex_id = await self.swap_thread_id_for_exchange_id(
                rec_id, "presentation-msg", "pres_ex_id"
            )
            agent_operation = (
                self.TopicTranslationDict[op["topic"]] + "records/" + pres_ex_id
            )

            (resp_status, resp_text) = await self.admin_GET(agent_operation)
            # if resp_status == 200: resp_text = self.agent_state_translation(op["topic"], None, resp_text)
            return (resp_status, resp_text)

        elif op["topic"] == "revocation":
            operation = op["operation"]
            (
                agent_operation,
                admin_data,
            ) = await self.get_agent_operation_acapy_version_based(
                op["topic"], operation, rec_id, data=None
            )

            (resp_status, resp_text) = await self.admin_GET(agent_operation)
            return (resp_status, resp_text)

        elif op["topic"] == "did-exchange":

            connection_id = rec_id
            agent_operation = "/connections/" + connection_id

            (resp_status, resp_text) = await self.admin_GET(agent_operation)
            if resp_status == 200:
                resp_text = self.agent_state_translation(op["topic"], None, resp_text)
            return (resp_status, resp_text)

        return (501, "501: Not Implemented\n\n".encode("utf8"))

    async def make_agent_DELETE_request(
        self, op, rec_id=None, data=None, text=False, params=None
    ) -> Tuple[int, str]:
        if op["topic"] == "credential" and rec_id:
            # swap thread id for cred ex id from the webhook
            # cred_ex_id = await self.swap_thread_id_for_exchange_id(rec_id, "credential-msg","credential_exchange_id")
            agent_operation = "/credential/" + rec_id
            # operation = op["operation"]
            # agent_operation, admin_data = await self.get_agent_operation_acapy_version_based(op["topic"], operation, rec_id, data)
            log_msg(agent_operation)

            (resp_status, resp_text) = await self.admin_DELETE(agent_operation)
            if resp_status == 200:
                resp_text = self.agent_state_translation(op["topic"], None, resp_text)
            return (resp_status, resp_text)

        return (501, "501: Not Implemented\n\n".encode("utf8"))

    async def make_agent_GET_request_response(
        self, topic, rec_id=None, text=False, params=None, message_name=None
    ) -> Tuple[int, str]:
        if topic == "connection" and rec_id:
            connection_msg = pop_resource(rec_id, "connection-msg")
            i = 0
            while connection_msg is None and i < MAX_TIMEOUT:
                await asyncio.sleep(1)
                connection_msg = pop_resource(rec_id, "connection-msg")
                i = i + 1

            resp_status = 200
            if connection_msg:
                resp_text = json.dumps(connection_msg)
            else:
                resp_text = "{}"

            return (resp_status, resp_text)

        if topic == "did-exchange" and rec_id:
            didexchange_msg = pop_resource(rec_id, "didexchange-msg")
            i = 0
            while didexchange_msg is None and i < MAX_TIMEOUT:
                await asyncio.sleep(1)
                didexchange_msg = pop_resource(rec_id, "didexchange-msg")
                i = i + 1

            resp_status = 200
            if didexchange_msg:
                resp_text = json.dumps(didexchange_msg)
                resp_text = self.agent_state_translation(topic, None, resp_text)
            else:
                resp_text = "{}"

            return (resp_status, resp_text)

        # Poping webhook messages wihtout an id is unusual. This code may be removed when issue 944 is fixed
        # see https://app.zenhub.com/workspaces/von---verifiable-organization-network-5adf53987ccbaa70597dbec0/issues/hyperledger/aries-cloudagent-python/944
        if topic == "did-exchange" and rec_id is None:
            await asyncio.sleep(1)
            if message_name is not None:
                didexchange_msg = pop_resource_latest(message_name)
            else:
                didexchange_msg = pop_resource_latest("connection-msg")
            i = 0
            while didexchange_msg is None and i < MAX_TIMEOUT:
                await asyncio.sleep(1)
                didexchange_msg = pop_resource_latest("connection-msg")
                i = i + 1

            resp_status = 200
            if didexchange_msg:
                resp_text = json.dumps(didexchange_msg)
                resp_text = self.agent_state_translation(topic, None, resp_text)
            else:
                resp_text = "{}"

            return (resp_status, resp_text)

        elif topic == "issue-credential" and rec_id:
            credential_msg = pop_resource(rec_id, "credential-msg")
            i = 0
            while credential_msg is None and i < MAX_TIMEOUT:
                await asyncio.sleep(1)
                credential_msg = pop_resource(rec_id, "credential-msg")
                i = i + 1

            resp_status = 200
            if credential_msg:
                resp_text = json.dumps(credential_msg)
            else:
                resp_text = "{}"

            return (resp_status, resp_text)

        elif topic == "credential" and rec_id:
            credential_msg = pop_resource(rec_id, "credential-msg")
            i = 0
            while credential_msg is None and i < MAX_TIMEOUT:
                await asyncio.sleep(1)
                credential_msg = pop_resource(rec_id, "credential-msg")
                i = i + 1

            resp_status = 200
            if credential_msg:
                resp_text = json.dumps(credential_msg)
            else:
                resp_text = "{}"

            return (resp_status, resp_text)

        elif topic == "proof" and rec_id:
            presentation_msg = pop_resource(rec_id, "presentation-msg")
            i = 0
            while presentation_msg is None and i < MAX_TIMEOUT:
                await asyncio.sleep(1)
                presentation_msg = pop_resource(rec_id, "presentation-msg")
                i = i + 1

            resp_status = 200
            if presentation_msg:
                resp_text = json.dumps(presentation_msg)
                if resp_status == 200:
                    resp_text = self.agent_state_translation(topic, None, resp_text)
            else:
                resp_text = "{}"

            return (resp_status, resp_text)

        elif topic == "revocation-registry" and rec_id:
            revocation_msg = pop_resource(rec_id, "revocation-registry-msg")
            i = 0
            while revocation_msg is None and i < MAX_TIMEOUT:
                await asyncio.sleep(1)
                revocation_msg = pop_resource(rec_id, "revocation-registry-msg")
                i = i + 1

            resp_status = 200
            if revocation_msg:
                resp_text = json.dumps(revocation_msg)
            else:
                resp_text = "{}"

            return (resp_status, resp_text)

        return (501, "501: Not Implemented\n\n".encode("utf8"))


async def main(start_port: int, show_timing: bool = False, interactive: bool = True):

    # check for extra args
    extra_args = {}
    if EXTRA_ARGS:
        print("Got extra args:", EXTRA_ARGS)
        extra_args = json.loads(EXTRA_ARGS)

    # genesis = await default_genesis_txns()
    # if not genesis:
    #     print("Error retrieving ledger genesis transactions")
    #     sys.exit(1)

    agent = None

    try:
        agent = IndiLynxCloudAgentBackchannel(
            "indiLynx." + AGENT_NAME,
            start_port + 1,
            start_port + 2,
            genesis_data="{}",
            extra_args=extra_args,
        )

        # start backchannel (common across all types of agents)
        await agent.listen_backchannel(start_port)

        #await agent.register_did()

        asyncio.get_event_loop().create_task(agent.start_listener())
        agent.activate()

        # now wait ...
        interactive = False
        print(interactive)
        if interactive:
            async for option in prompt_loop("(X) Exit? [X] "):
                if option is None or option in "xX":
                    break
        else:
            print("Press Ctrl-C to exit ...")
            remaining_tasks = asyncio.Task.all_tasks()
            await asyncio.gather(*remaining_tasks)

    finally:
        terminated = True
        try:
            if agent:
                await agent.terminate()
        except Exception:
            LOGGER.exception("Error terminating agent:")
            terminated = False

    await asyncio.sleep(0.1)

    if not terminated:
        os._exit(1)


def str2bool(v):
    if isinstance(v, bool):
        return v
    if v.lower() in ("yes", "true", "t", "y", "1"):
        return True
    elif v.lower() in ("no", "false", "f", "n", "0"):
        return False
    else:
        raise argparse.ArgumentTypeError("Boolean value expected.")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Runs a Faber demo agent.")
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=8020,
        metavar=("<port>"),
        help="Choose the starting port number to listen on",
    )
    parser.add_argument(
        "-i",
        "--interactive",
        type=str2bool,
        default=True,
        metavar=("<interactive>"),
        help="Start agent interactively",
    )
    args = parser.parse_args()

    if "acme" in AGENT_NAME.lower():
        test_agent_name = "agent1"
    elif "bob" in AGENT_NAME.lower():
        test_agent_name = "agent2"
    elif "faber" in AGENT_NAME.lower():
        test_agent_name = "agent3"
    elif "mallory" in AGENT_NAME.lower():
        test_agent_name = "agent4"
    else:
        test_agent_name = "agent1"

    gov_agent_params = asyncio.get_event_loop().run_until_complete(get_agent_params(test_agent_name))
    sirius_sdk.init(**gov_agent_params)

    try:
        asyncio.get_event_loop().run_until_complete(
            main(start_port=args.port, interactive=args.interactive)
        )
    except KeyboardInterrupt:
        os._exit(1)
