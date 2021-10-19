import asyncio
import functools
import json
import logging
import os
import subprocess
import sys
import uuid

from timeit import default_timer
from typing import Tuple

from aiohttp import (
    web,
    ClientSession,
    ClientRequest,
    ClientError,
    ClientTimeout,
)

from python.agent_backchannel import (
    AgentBackchannel,
    default_genesis_txns,
    RUN_MODE,
    START_TIMEOUT,
)
from python.utils import flatten, log_msg, output_reader, prompt_loop
from python.storage import (
    get_resource,
    push_resource,
    pop_resource,
    pop_resource_latest,
)
import sirius_sdk

# from helpers.jsonmapper.json_mapper import JsonMapper

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

        self.invitations = dict()

    async def listen_webhooks(self, webhook_port):
        self.webhook_port = webhook_port
        if RUN_MODE == "pwd":
            self.webhook_url = f"http://localhost:{str(webhook_port)}/webhooks"
        else:
            self.webhook_url = (
                f"http://{self.external_host}:{str(webhook_port)}/webhooks"
            )
        app = web.Application()
        app.add_routes([web.post("/webhooks/topic/{topic}/", self._receive_webhook)])
        runner = web.AppRunner(app)
        await runner.setup()
        self.webhook_site = web.TCPSite(runner, "0.0.0.0", webhook_port)
        await self.webhook_site.start()
        print("Listening to web_hooks on port", webhook_port)

    async def _receive_webhook(self, request: ClientRequest):
        topic = request.match_info["topic"]
        payload = await request.json()
        await self.handle_webhook(topic, payload)
        # TODO web hooks don't require a response???
        return web.Response(text="")

    async def handle_webhook(self, topic: str, payload):
        if topic != "webhook":  # would recurse
            handler = f"handle_{topic}"

            # Remove this handler change when bug is fixed.
            if handler == "handle_oob-invitation":
                handler = "handle_oob_invitation"

            method = getattr(self, handler, None)
            # put a log message here
            log_msg("Passing webhook payload to handler " + handler)
            if method:
                await method(payload)
            else:
                log_msg(
                    f"Error: agent {self.ident} "
                    f"has no method {handler} "
                    f"to handle webhook on topic {topic}"
                )
        else:
            log_msg(
                "in webhook, topic is: " + topic + " payload is: " + json.dumps(payload)
            )

    async def handle_connections(self, message):
        if "request_id" in message:
            # This is a did-exchange message based on a Public DID non-invitation
            request_id = message["request_id"]
            push_resource(request_id, "didexchange-msg", message)
        elif message["connection_protocol"] == "didexchange/1.0":
            # This is an did-exchange message based on a Non-Public DID invitation
            invitation_id = message["invitation_msg_id"]
            push_resource(invitation_id, "didexchange-msg", message)
        elif message["connection_protocol"] == "connections/1.0":
            connection_id = message["connection_id"]
            push_resource(connection_id, "connection-msg", message)
        else:
            raise Exception(
                f"Unknown message type in Connections Webhook: {json.dumps(message)}"
            )
        log_msg("Received a Connection Webhook message: " + json.dumps(message))

    async def handle_issue_credential(self, message):
        thread_id = message["thread_id"]
        push_resource(thread_id, "credential-msg", message)
        log_msg("Received Issue Credential Webhook message: " + json.dumps(message))
        if "revocation_id" in message:  # also push as a revocation message
            push_resource(thread_id, "revocation-registry-msg", message)
            log_msg("Issue Credential Webhook message contains revocation info")

    async def handle_issue_credential_v2_0(self, message):
        thread_id = message["thread_id"]
        push_resource(thread_id, "credential-msg", message)
        log_msg("Received Issue Credential v2 Webhook message: " + json.dumps(message))
        if "revocation_id" in message:  # also push as a revocation message
            push_resource(thread_id, "revocation-registry-msg", message)
            log_msg("Issue Credential Webhook message contains revocation info")

    async def handle_present_proof_v2_0(self, message):
        thread_id = message["thread_id"]
        push_resource(thread_id, "presentation-msg", message)
        log_msg("Received a Present Proof v2 Webhook message: " + json.dumps(message))

    async def handle_present_proof(self, message):
        thread_id = message["thread_id"]
        push_resource(thread_id, "presentation-msg", message)
        log_msg("Received a Present Proof Webhook message: " + json.dumps(message))

    async def handle_revocation_registry(self, message):
        # No thread id in the webhook for revocation registry messages
        cred_def_id = message["cred_def_id"]
        push_resource(cred_def_id, "revocation-registry-msg", message)
        log_msg("Received Revocation Registry Webhook message: " + json.dumps(message))

    # TODO Handle handle_issuer_cred_rev (this must be newer than the revocation tests?)
    # TODO Handle handle_issue_credential_v2_0_indy

    async def handle_oob_invitation(self, message):
        # No thread id in the webhook for revocation registry messages
        invitation_id = message["invitation_id"]
        push_resource(invitation_id, "oob-inviation-msg", message)
        log_msg(
            "Received Out of Band Invitation Webhook message: " + json.dumps(message)
        )

    async def handle_problem_report(self, message):
        thread_id = message["thread_id"]
        push_resource(thread_id, "problem-report-msg", message)
        log_msg("Received Problem Report Webhook message: " + json.dumps(message))

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
                return 200, str({
                    "connection_id": connection_key,
                    "invitation": invitation
                })

            elif operation == "receive-invitation":
                invitation = sirius_sdk.aries_rfc.Invitation(**dict(data))
                invitation.validate()
                connection_id = str(uuid.uuid1())
                self.invitations[connection_id] = invitation
                return 200, str({
                    "connection_id": connection_id,
                    "state": "invitation"
                })

            elif operation == "accept-invitation":
                connection_id = rec_id
                invitation = self.invitations[connection_id]
                did, verkey = await sirius_sdk.DID.create_and_store_my_did()
                me = sirius_sdk.Pairwise.Me(did, verkey)
                my_endpoint = [e for e in await sirius_sdk.endpoints() if e.routing_keys == []][0]
                invitee = sirius_sdk.aries_rfc.Invitee(me, my_endpoint)
                ok, pairwise = await invitee.create_connection(invitation=invitation, my_label='IndiLynx Invitee')
                if ok:
                    del self.invitations[connection_id]
                    return 200, str({
                        "connection_id": connection_id,
                        "state": "active"
                    })
                else:
                    return 200, str({
                        "connection_id": connection_id,
                        "state": "request"
                    })

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
            return (status, json.dumps({"status": status_msg}))

        if op["topic"] == "version":
            if self.acapy_version is not None:
                status = 200
                # status_msg = json.dumps({"version": self.acapy_version})
                status_msg = self.acapy_version
            else:
                status = 404
                # status_msg = json.dumps({"version": "not found"})
                status_msg = "not found"
            return (status, status_msg)

        elif op["topic"] == "connection":
            if rec_id:
                connection_id = rec_id
                agent_operation = "/connections/" + connection_id
            else:
                agent_operation = "/connections"

            log_msg("GET Request agent operation: ", agent_operation)

            (resp_status, resp_text) = await self.admin_GET(agent_operation)
            if resp_status != 200:
                return (resp_status, resp_text)

            log_msg("GET Request response details: ", resp_status, resp_text)

            resp_json = json.loads(resp_text)
            if rec_id:
                connection_info = {
                    "connection_id": resp_json["connection_id"],
                    "state": resp_json["state"],
                    "connection": resp_json,
                }
                resp_text = json.dumps(connection_info)
            else:
                resp_json = resp_json["results"]
                connection_infos = []
                for connection in resp_json:
                    connection_info = {
                        "connection_id": connection["connection_id"],
                        "state": connection["state"],
                        "connection": connection,
                    }
                    connection_infos.append(connection_info)
                resp_text = json.dumps(connection_infos)
            # translate the state from that the agent gave to what the tests expect
            resp_text = self.agent_state_translation(op["topic"], None, resp_text)
            return (resp_status, resp_text)

        elif op["topic"] == "did":
            agent_operation = "/wallet/did/public"

            (resp_status, resp_text) = await self.admin_GET(agent_operation)
            if resp_status != 200:
                return (resp_status, resp_text)

            resp_json = json.loads(resp_text)
            did = resp_json["result"]

            resp_text = json.dumps(did)
            return (resp_status, resp_text)

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
            agent_operation = "/schemas/" + schema_id

            (resp_status, resp_text) = await self.admin_GET(agent_operation)
            if resp_status != 200:
                return (resp_status, resp_text)

            resp_json = json.loads(resp_text)
            schema = resp_json["schema"]

            resp_text = json.dumps(schema)
            return (resp_status, resp_text)

        elif op["topic"] == "credential-definition":
            cred_def_id = rec_id
            agent_operation = "/credential-definitions/" + cred_def_id

            (resp_status, resp_text) = await self.admin_GET(agent_operation)
            if resp_status != 200:
                return (resp_status, resp_text)

            resp_json = json.loads(resp_text)
            credential_definition = resp_json["credential_definition"]

            resp_text = json.dumps(credential_definition)
            return (resp_status, resp_text)

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

    def _process(self, args, env, loop):
        proc = subprocess.Popen(
            args,
            env=env,
            encoding="utf-8",
        )
        loop.run_in_executor(
            None,
            output_reader,
            proc.stdout,
            functools.partial(self.handle_output, source="stdout"),
        )
        loop.run_in_executor(
            None,
            output_reader,
            proc.stderr,
            functools.partial(self.handle_output, source="stderr"),
        )
        return proc

    def get_process_args(self, bin_path: str = None):
        # TODO aca-py needs to be in the path so no need to give it a cmd_path
        cmd_path = "aca-py"
        if bin_path is None:
            bin_path = DEFAULT_BIN_PATH
        if bin_path:
            cmd_path = os.path.join(bin_path, cmd_path)
        print("Location of ACA-Py: " + cmd_path)
        if self.get_acapy_version_as_float() > 56:
            return list(flatten(([cmd_path, "start"], self.get_agent_args())))
        else:
            return list(
                flatten((["python3", cmd_path, "start"], self.get_agent_args()))
            )

    async def detect_process(self):
        # text = None

        async def fetch_swagger(url: str, timeout: float):
            text = None
            start = default_timer()
            async with ClientSession(timeout=ClientTimeout(total=3.0)) as session:
                while default_timer() - start < timeout:
                    try:
                        async with session.get(url) as resp:
                            if resp.status == 200:
                                text = await resp.text()
                                break
                    except (ClientError, asyncio.TimeoutError):
                        pass
                    await asyncio.sleep(0.5)
            return text

        status_url = self.admin_url + "/status"
        status_text = await fetch_swagger(status_url, START_TIMEOUT)
        print("Agent running with admin url", self.admin_url)

        if not status_text:
            raise Exception(
                "Timed out waiting for agent process to start. "
                + f"Admin URL: {status_url}"
            )
        ok = False
        try:
            status = json.loads(status_text)
            ok = isinstance(status, dict) and "version" in status
            if ok:
                self.acapy_version = status["version"]
                print(
                    "ACA-py Backchannel running with ACA-py version:",
                    self.acapy_version,
                )
        except json.JSONDecodeError:
            pass
        if not ok:
            raise Exception(
                f"Unexpected response from agent process. Admin URL: {status_url}"
            )

    async def start_process(
        self, python_path: str = None, bin_path: str = None, wait: bool = True
    ):
        my_env = os.environ.copy()
        python_path = DEFAULT_PYTHON_PATH if python_path is None else python_path
        if python_path:
            my_env["PYTHONPATH"] = python_path

        agent_args = self.get_process_args(bin_path)

        # start agent sub-process
        self.log(f"Starting agent sub-process ...")
        self.log(f"agent starting with params: ")
        self.log(agent_args)
        loop = asyncio.get_event_loop()
        self.proc = await loop.run_in_executor(
            None, self._process, agent_args, my_env, loop
        )
        if wait:
            await asyncio.sleep(1.0)
            await self.detect_process()

    def _terminate(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=0.5)
                self.log(f"Exited with return code {self.proc.returncode}")
            except subprocess.TimeoutExpired:
                msg = "Process did not terminate in time"
                self.log(msg)
                raise Exception(msg)

    async def terminate(self):
        loop = asyncio.get_event_loop()
        if self.proc:
            await loop.run_in_executor(None, self._terminate)
        await self.client_session.close()
        if self.webhook_site:
            await self.webhook_site.stop()


async def main(start_port: int, show_timing: bool = False, interactive: bool = True):

    # check for extra args
    extra_args = {}
    if EXTRA_ARGS:
        print("Got extra args:", EXTRA_ARGS)
        extra_args = json.loads(EXTRA_ARGS)

    genesis = await default_genesis_txns()
    if not genesis:
        print("Error retrieving ledger genesis transactions")
        sys.exit(1)

    agent = None

    try:
        agent = IndiLynxCloudAgentBackchannel(
            "indiLynx." + AGENT_NAME,
            start_port + 1,
            start_port + 2,
            genesis_data=genesis,
            extra_args=extra_args,
        )

        # start backchannel (common across all types of agents)
        await agent.listen_backchannel(start_port)

        # start aca-py agent sub-process and listen for web hooks
        await agent.listen_webhooks(start_port + 3)
        await agent.register_did()

        await agent.start_process()
        agent.activate()

        # now wait ...
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

    try:
        asyncio.get_event_loop().run_until_complete(
            main(start_port=args.port, interactive=args.interactive)
        )
    except KeyboardInterrupt:
        os._exit(1)
