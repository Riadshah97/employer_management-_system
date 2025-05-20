from rest_framework.views import APIView
from rest_framework.response import Response
import logging

logger = logging.getLogger(__name__)

class ApiView(APIView):
    """Base API View class with common functionality"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)