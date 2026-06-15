"""
CyTrack Custom Exception Handler
==================================
Wraps DRF's default exception handler to return consistent error envelopes.
"""
import logging
from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status

logger = logging.getLogger(__name__)


def cytrack_exception_handler(exc, context):
    """
    Custom DRF exception handler.

    Ensures all API errors return a consistent shape:
    {
        "error": {
            "code": "HTTP_STATUS_CODE",
            "message": "Human-readable description",
            "detail": <DRF detail object>
        }
    }
    """
    response = exception_handler(exc, context)

    if response is not None:
        view = context.get('view')
        request = context.get('request')

        error_data = {
            'error': {
                'code': response.status_code,
                'message': _status_message(response.status_code),
                'detail': response.data,
            }
        }

        logger.warning(
            'API error %s on %s %s: %s',
            response.status_code,
            request.method if request else 'UNKNOWN',
            request.path if request else 'UNKNOWN',
            response.data,
        )

        response.data = error_data

    return response


def _status_message(code):
    messages = {
        400: 'Bad Request',
        401: 'Authentication required',
        403: 'Permission denied',
        404: 'Resource not found',
        405: 'Method not allowed',
        409: 'Conflict',
        429: 'Too many requests',
        500: 'Internal server error',
    }
    return messages.get(code, 'An error occurred')
