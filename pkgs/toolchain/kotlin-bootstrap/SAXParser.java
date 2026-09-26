package org.apache.xerces.parsers;

import java.io.IOException;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParserFactory;
import org.xml.sax.ContentHandler;
import org.xml.sax.DTDHandler;
import org.xml.sax.EntityResolver;
import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXNotRecognizedException;
import org.xml.sax.SAXNotSupportedException;
import org.xml.sax.XMLReader;

/** Supplies JDOM's historical parser name using the source-built JDK parser. */
public final class SAXParser implements XMLReader {
    private final XMLReader delegate;

    public SAXParser() throws SAXException {
        try {
            delegate = SAXParserFactory.newInstance().newSAXParser().getXMLReader();
        } catch (ParserConfigurationException exception) {
            throw new SAXException("Cannot configure the JDK SAX parser", exception);
        }
    }

    public boolean getFeature(String name)
            throws SAXNotRecognizedException, SAXNotSupportedException {
        return delegate.getFeature(name);
    }

    public void setFeature(String name, boolean value)
            throws SAXNotRecognizedException, SAXNotSupportedException {
        delegate.setFeature(name, value);
    }

    public Object getProperty(String name)
            throws SAXNotRecognizedException, SAXNotSupportedException {
        return delegate.getProperty(name);
    }

    public void setProperty(String name, Object value)
            throws SAXNotRecognizedException, SAXNotSupportedException {
        delegate.setProperty(name, value);
    }

    public void setEntityResolver(EntityResolver resolver) {
        delegate.setEntityResolver(resolver);
    }

    public EntityResolver getEntityResolver() {
        return delegate.getEntityResolver();
    }

    public void setDTDHandler(DTDHandler handler) {
        delegate.setDTDHandler(handler);
    }

    public DTDHandler getDTDHandler() {
        return delegate.getDTDHandler();
    }

    public void setContentHandler(ContentHandler handler) {
        delegate.setContentHandler(handler);
    }

    public ContentHandler getContentHandler() {
        return delegate.getContentHandler();
    }

    public void setErrorHandler(ErrorHandler handler) {
        delegate.setErrorHandler(handler);
    }

    public ErrorHandler getErrorHandler() {
        return delegate.getErrorHandler();
    }

    public void parse(InputSource source) throws IOException, SAXException {
        delegate.parse(source);
    }

    public void parse(String systemId) throws IOException, SAXException {
        delegate.parse(systemId);
    }
}
