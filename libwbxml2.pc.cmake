prefix=@CMAKE_INSTALL_PREFIX@
exec_prefix=@LIBWBXML_EXEC_INSTALL_DIR@
libdir=@LIBWBXML_LIBRARIES_DIR@
includedir=@LIBWBXML_INCLUDE_DIR@

Name: libwbxml2
Description: C wbxml library
Version: @LIBWBXML_VERSION@
Requires: libxml-2.0 >= 2.6
Libs: -L${libdir} -lwbxml2
Cflags: -I${includedir}
