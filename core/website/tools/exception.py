from rest_framework import status
from rest_framework.exceptions import APIException
from django.utils.encoding import force_text


"""Exceptions"""
class CustomException(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'there is a problem with your entered information'
    default_code = 'error'

    def __init__(self, detail, field, status_code):
        if status_code is not None:self.status_code = status_code
        if detail is not None:
            self.detail = {field: force_text(detail)}
        else: self.detail = {'detail': force_text(self.default_detail)}