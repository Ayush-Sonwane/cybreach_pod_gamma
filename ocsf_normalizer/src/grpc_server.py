import logging
import os
import threading
import time
from concurrent import futures

import grpc

try:
    import sys
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
    from proto import cybreach_service_pb2, cybreach_service_pb2_grpc
except ImportError:  # pragma: no cover - generated stubs are created during build
    cybreach_service_pb2 = None
    cybreach_service_pb2_grpc = None

logger = logging.getLogger(__name__)


class NormalizationServiceServicer:
    def Normalize(self, request, context):
        if cybreach_service_pb2 is None:
            context.abort(grpc.StatusCode.UNIMPLEMENTED, "gRPC stubs not generated")
        return cybreach_service_pb2.NormalizeResponse(
            evidence_id=request.evidence_id,
            normalized_event=b'{"normalized": true}',
            status="ok",
            error_detail="",
        )

    def HealthCheck(self, request, context):
        if cybreach_service_pb2 is None:
            context.abort(grpc.StatusCode.UNIMPLEMENTED, "gRPC stubs not generated")
        return cybreach_service_pb2.HealthResponse(
            status="ok",
            service="gamma-normalizer",
            timestamp=int(time.time()),
            version="1.0",
        )


def serve(host: str = "0.0.0.0", port: int = 50053):
    if cybreach_service_pb2 is None or cybreach_service_pb2_grpc is None:
        logger.warning(
            "Gamma gRPC server not started because proto stubs are not generated. "
            "Run: python -m grpc_tools.protoc -Iproto --python_out=. --grpc_python_out=. proto/cybreach_service.proto"
        )
        return

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    cybreach_service_pb2_grpc.add_NormalizationServiceServicer_to_server(
        NormalizationServiceServicer(),
        server,
    )
    server.add_insecure_port(f"{host}:{port}")
    server.start()
    logger.info("[Gamma gRPC] NormalizationService listening on %s:%s", host, port)
    server.wait_for_termination()
