## Process this file with automake to produce Makefile.in

# The name of the module.
DOC_MODULE=prelude

# The top-level SGML file.
DOC_MAIN_SGML_FILE=prelude-api.sgml

# The directory containing the source code (if it contains documentation).
DOC_SOURCE_DIR=$(top_srcdir)/src/prelude

TARGET_DIR=$(HTML_DIR)/$(DOC_MODULE)

prelude_docdir = $(HTML_DIR)
prelude_doc_DATA = \
	prelude-api.sgml 	\
	prelude-api.html	\
	prelude-decl.txt	\
	prelude-sections.txt

EXTRA_DIST = $(prelude_doc_DATA)

if ENABLE_GTK_DOC
prelude-api.html: html/book1.html
	-cp $(srcdir)/html/book1.html $(srcdir)/html/prelude-api.html
else
prelude-api.html:
endif

html/book1.html: sgml/prelude-doc.bottom
	$(MAKE) html

sgml/prelude-doc.bottom: $(tmpl_sources)
	$(MAKE) sgml


scan:
	gtkdoc-scan --module=$(DOC_MODULE) $(top_srcdir)/src/prelude/include/*.h; 

templates:
	cd $(srcdir) && gtkdoc-mktmpl --module=$(DOC_MODULE)

sgml:
	cd $(srcdir) \
	&& gtkdoc-mkdb --module=$(DOC_MODULE) --source-dir=$(DOC_SOURCE_DIR)

html:
	test -d $(srcdir)/html || mkdir $(srcdir)/html 
	-cd $(srcdir)/html && gtkdoc-mkhtml $(DOC_MODULE) ../$(DOC_MAIN_SGML_FILE)


clean-local:
	rm -f *~ *.bak *.hierarchy *.signals *.args *-unused.txt


maintainer-clean-local: clean
	cd $(srcdir) && rm -rf sgml html $(DOC_MODULE)-decl-list.txt $(DOC_MODULE)-decl.txt 


install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(TARGET_DIR)
	(installfiles=`echo $(srcdir)/html/*.html`; \
	if test "$$installfiles" = '$(srcdir)/html/*.html'; \
	then echo '-- Nothing to install' ; \
	else \
		for i in $$installfiles; do \
			echo '-- Installing '$$i ; \
			 $(INSTALL_DATA) $$i $(DESTDIR)$(TARGET_DIR); \
	done; \
	echo '-- Installing $(srcdir)/html/index.sgml' ; \
	$(INSTALL_DATA) $(srcdir)/html/index.sgml $(DESTDIR)$(TARGET_DIR); \
	echo '-- Fixing Crossreferences' ; \
	gtkdoc-fixxref --module=$(DOC_MODULE) --html-dir=$(HTML_DIR)|| true; \
	fi)

dist-hook:
	mkdir $(distdir)/html
	mkdir $(distdir)/sgml
	mkdir $(distdir)/tmpl
	-cp $(srcdir)/html/*.html $(srcdir)/html/*.css $(distdir)/html
	-cp $(srcdir)/tmpl/*.sgml $(distdir)/tmpl
	-cp $(srcdir)/sgml/*.sgml $(distdir)/sgml
	-cp $(srcdir)/sgml/*.bottom $(srcdir)/sgml/*.top $(distdir)/sgml


.PHONY : html sgml templates scan
