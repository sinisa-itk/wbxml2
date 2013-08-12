include "types.pxi"

cdef extern from "wbxml_conv.h":
    WBXMLError wbxml_conv_wbxml2xml_withlen(WB_UTINY *wbxml, WB_ULONG wbxml_len, WB_UTINY **xml, WB_ULONG *xml_len, WBXMLGenXMLParams *params)
    WBXMLError wbxml_conv_xml2wbxml_withlen(WB_UTINY *xml, WB_ULONG xml_len, WB_UTINY **wbxml, WB_ULONG *wbxml_len, WBXMLGenWBXMLParams *params)
    WB_UTINY *wbxml_errors_string(WBXMLError error_code)

cdef extern from "stdlib.h":
    void *malloc(size_t size)
    void free(void *ptr)

cdef extern from "Python.h":
    char *PyString_AsString(object string)
    object PyString_FromStringAndSize(char *s, int len)
    int PyString_AsStringAndSize(object obj, char **buffer, int *length)

class WBXMLParseError(BaseException):
    def __init__(self, code):
        self.code = code
        self.description = <char *> wbxml_errors_string(code)

    def __str__(self):
        return "%s (%d)" % (self.description, self.code)

def wbxml2xml(wbxml):
    cdef WB_UTINY *xml
    cdef WB_ULONG xml_len
    cdef WBXMLGenXMLParams params

    params.gen_type = WBXML_GEN_XML_CANONICAL
    params.lang = WBXML_LANG_AIRSYNC
    params.indent = 0
    params.keep_ignorable_ws = 1

    retval = wbxml_conv_wbxml2xml_withlen(<WB_UTINY *> PyString_AsString(wbxml), len(wbxml), &xml, &xml_len, &params)
    if retval != 0:
        raise WBXMLParseError(retval)

    s = PyString_FromStringAndSize(<char *> xml, xml_len)
    free(xml)

    return s

def xml2wbxml(xml):
    cdef char *xml_raw
    cdef int xml_raw_len
    cdef WB_UTINY *bytes
    cdef WB_ULONG size
    cdef WBXMLGenWBXMLParams params

    params.wbxml_version = WBXML_VERSION_13
    params.keep_ignorable_ws = 1
    params.use_strtbl = 0
    params.produce_anonymous = 1

    if isinstance(xml, unicode):
        xml = xml.encode("utf-8")

    if PyString_AsStringAndSize(xml, &xml_raw, &xml_raw_len) == -1:
        raise TypeError("invalid string")

    retval = wbxml_conv_xml2wbxml_withlen(<WB_UTINY *> xml_raw, xml_raw_len, &bytes, &size, &params)
    if retval != 0:
        raise WBXMLParseError(retval)

    s = PyString_FromStringAndSize(<char *> bytes, size)
    free(bytes)

    return s
