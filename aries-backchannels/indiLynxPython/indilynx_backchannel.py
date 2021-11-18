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
        self.referent: str = None
        self.schema_id: str = None
        self.cred_def_id: str = None
        self.thread_id: str = None


class IndiLynxPresentationExchangeRecord:

    def __init__(self):
        self.thread_id: str = None


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
        self.presentations = []
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
            elif isinstance(request, sirius_sdk.aries_rfc.RequestPresentationMessage):
                pres_req: sirius_sdk.aries_rfc.RequestPresentationMessage = request
                verifier = event.pairwise
                dkms = sirius_sdk.ledger(self.dkms_name)
                holder_machine = sirius_sdk.aries_rfc.Prover(
                    verifier=verifier,
                    ledger=dkms,
                    logger=Logger()
                )
                pres_ex_record = IndiLynxPresentationExchangeRecord()
                pres_ex_record.thread_id = pres_req.id
                self.presentations.append(pres_ex_record)
                success = await holder_machine.prove(
                    request=pres_req,
                    master_secret_id=self.master_secret_id
                )

    async def start_dummy_listener(self):
        listener = await sirius_sdk.subscribe()
        print("Listening 2")
        async for event in listener:
            log_msg("Received event: " + str(event))

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
            schema_name = data["schema_name"]
            schema_version = data["schema_version"]
            attributes = data["attributes"]
            schema_id, anoncred_schema = await sirius_sdk.AnonCreds.issuer_create_schema(issuer_did=self.did["did"],
                                                            name=schema_name,
                                                            version=schema_version,
                                                            attrs=attributes)
            dkms = await sirius_sdk.ledger(self.dkms_name)
            ok, schema = await dkms.register_schema(anoncred_schema, self.did["did"])
            if ok:
                return 200, json.dumps({
                    "schema_id": schema_id,
                    "schema": schema
                })
            else:
                return 500, "Failed to register schema"

        elif op["topic"] == "credential-definition":
            support_revocation = data["support_revocation"]
            schema_id = data["schema_id"]
            tag = data["tag"]

            dkms = await sirius_sdk.ledger(self.dkms_name)
            schema = await dkms.load_schema(schema_id, self.did["did"])
            ok, cred_def = await dkms.register_cred_def(
                cred_def=sirius_sdk.CredentialDefinition(tag='TAG', schema=schema),
                submitter_did=self.did["did"])
            if ok:
                return 200, json.dumps({
                    "credential_definition_id": cred_def.id
                })
            else:
                return 500, "Failed to create cred def"

        elif op["topic"] == "issue-credential":
            operation = op["operation"]
            if operation == "send-proposal":
                connection_id = data["connection_id"]
                if connection_id in self.connections:
                    if self.connections[connection_id].state == IndiLynxConnection.State.complete:
                        pw: sirius_sdk.Pairwise = self.connections[connection_id].pairwise
                        proposed_attribs = []
                        for attr in data["credential_proposal"]["attributes"]:
                            proposed_attribs += sirius_sdk.aries_rfc.ProposedAttrib(attr["name"], attr["value"])
                        proposal = sirius_sdk.aries_rfc.ProposeCredentialMessage(
                            comment=data["comment"],
                            proposal_attrib=proposed_attribs,
                            schema_id=data["schema_id"],
                            schema_name=data["schema_name"],
                            schema_version=data["schema_version"],
                            schema_issuer_did=data["schema_issuer_did"],
                            cred_def_id=data["cred_def_id"],
                            issuer_did=data["issuer_did"]
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
                connection_id = data["connection_id"]
                pw: sirius_sdk.Pairwise = self.connections[connection_id].pairwise
                issuer_machine = sirius_sdk.aries_rfc.Issuer(holder=pw)
                values = {}
                for attr in data["credential_preview"]["attributes"]:
                    values[attr["name"]] = attr["value"]
                proposal: sirius_sdk.aries_rfc.ProposeCredentialMessage = self.issuing[connection_id].proposal

                dkms = await sirius_sdk.ledger(self.dkms_name)
                schema = await dkms.load_schema(proposal.schema_id, self.did["did"])
                cred_def = await dkms.load_cred_def(proposal.cred_def_id, self.did["did"])
                credential_id = self.issuing[connection_id].credential_id
                ok = await issuer_machine.issue(
                    values=values,
                    comment=data["comment"],
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
        elif op["topic"] == "proof":
            operation = op["operation"]
            if operation == "send-proposal":
                return 500, "Not implemented"
            elif operation == "send-request":
                connection_id = data["connection_id"]
                presentation_request = data["presentation_request"]
                comment = presentation_request["comment"]
                proof_request = presentation_request["proof_request"]["data"]

                prover_pairwise = self.connections[connection_id].pairwise
                dkms = await sirius_sdk.ledger(self.dkms_name)
                verifier_machine = sirius_sdk.aries_rfc.Verifier(
                    prover=prover_pairwise,
                    ledger=dkms,
                    logger=Logger()
                )

                pres_ex_record = IndiLynxPresentationExchangeRecord()
                self.presentations.append(pres_ex_record)

                success = await verifier_machine.verify(proof_request)
                if success:
                    return 200, json.dumps({
                        "state": "done",
                        #"thread_id":
                    })
            elif operation == "send-presentation":
                return 200, json.dumps({

                })

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
            if self.did:
                return 200, json.dumps({
                    "did": self.did["did"],
                    "verkey": self.did["verkey"]
                })

        elif op["topic"] == "active-connection" and rec_id:
            return 500, "Not implemented"

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
            for conn_id in self.issuing:
                iss: IndiLynxIssuing = self.issuing[conn_id]
                if iss.thread_id == rec_id:
                    return 200, json.dumps({
                        "thread_id": iss.thread_id,
                        "credential_id": iss.credential_id
                    })
            return 500, f"Cred {rec_id} not found"

        elif op["topic"] == "issue-credential-v2":
            return 500, "Not implemented"

        elif op["topic"] == "credential":
            for conn_id in self.issuing:
                iss: IndiLynxIssuing = self.issuing[conn_id]
                if iss.credential_id == rec_id:
                    return 200, json.dumps({
                        "referent": iss.referent,
                        "schema_id": iss.schema_id,
                        "cred_def_id": iss.cred_def_id
                    })
            return 404, f"Cred {rec_id} not found"

        elif op["topic"] == "proof":
            for presentation in self.presentations:
                if presentation.thread_id == rec_id:
                    return 200, json.dumps({
                        "thread_id": presentation.thread_id
                    })
            return 404, f"Presentation exchange record with thread id {rec_id} not found"

        return 501, "501: Not Implemented\n\n".encode("utf8")

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


async def main(start_port: int, show_timing: bool = False, interactive: bool = True, did=None):

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

        agent.did = did

        # start backchannel (common across all types of agents)
        await agent.listen_backchannel(start_port)

        #await agent.register_did()

        asyncio.get_event_loop().create_task(agent.start_listener())
        asyncio.get_event_loop().create_task(agent.start_dummy_listener())
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

    gov_agent_params, did = asyncio.get_event_loop().run_until_complete(get_agent_params(test_agent_name))
    sirius_sdk.init(**gov_agent_params)

    try:
        asyncio.get_event_loop().run_until_complete(
            main(start_port=args.port, interactive=args.interactive, did=did)
        )
    except KeyboardInterrupt:
        os._exit(1)
