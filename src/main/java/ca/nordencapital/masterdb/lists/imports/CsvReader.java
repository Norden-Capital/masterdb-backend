package ca.nordencapital.masterdb.lists.imports;

import java.io.Closeable;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;

/**
 * Reads a .txt or .csv file one record at a time, never the whole file.
 * Fields are separated by {@code delimiter} ({@code 0} = one field per line);
 * a field starting with {@code "} is quoted ({@code ""} inside is one quote,
 * line breaks inside are kept). Lines end with LF, CRLF or CR. A UTF-8 byte
 * order mark at the start is dropped. A record longer than
 * {@code maxRecordChars} stops the read with a clear message (usually a quote
 * that was never closed).
 */
public final class CsvReader implements Closeable {

    /** A file that can't be read as CSV, with a sentence for the user. */
    public static final class CsvException extends IOException {
        public CsvException(String message) {
            super(message);
        }
    }

    private final Reader in;
    private final char delimiter;
    private final int maxRecordChars;
    private final char[] buf = new char[64 * 1024];
    private int pos;
    private int len;
    private boolean eof;
    private boolean first = true;
    private long line = 1;

    public CsvReader(Reader in, char delimiter, int maxRecordChars) {
        this.in = in;
        this.delimiter = delimiter;
        this.maxRecordChars = maxRecordChars;
    }

    /** The line the next record starts on (1-based). */
    public long line() {
        return line;
    }

    private int read() throws IOException {
        if (pos >= len) {
            if (eof) {
                return -1;
            }
            len = in.read(buf, 0, buf.length);
            pos = 0;
            if (len <= 0) {
                eof = true;
                len = 0;
                return -1;
            }
        }
        return buf[pos++];
    }

    private int peek() throws IOException {
        int c = read();
        if (c >= 0) {
            pos--;
        }
        return c;
    }

    /** The next record's fields, or null at the end of the file. A blank line is a record with one empty field. */
    public List<String> next() throws IOException {
        int c = read();
        if (first) {
            first = false;
            if (c == '﻿') {
                c = read();
            }
        }
        if (c < 0) {
            return null;
        }
        long startLine = line;
        List<String> fields = new ArrayList<>();
        StringBuilder field = new StringBuilder();
        int size = 0;
        boolean quoted = false;
        boolean fieldStart = true;
        while (true) {
            if (c < 0) {
                fields.add(field.toString());
                return fields;
            }
            if (++size > maxRecordChars) {
                throw new CsvException("Line " + startLine + " is longer than " + maxRecordChars + " characters"
                        + (quoted ? ": a quote (\") is probably never closed." : "."));
            }
            if (quoted) {
                if (c == '"') {
                    if (peek() == '"') {
                        read();
                        field.append('"');
                    } else {
                        quoted = false;
                    }
                } else {
                    if (c == '\n' || (c == '\r' && peek() != '\n')) {
                        line++;
                    }
                    field.append((char) c);
                }
            } else if (c == '"' && fieldStart) {
                quoted = true;
                fieldStart = false;
            } else if (delimiter != 0 && c == delimiter) {
                fields.add(field.toString());
                field.setLength(0);
                fieldStart = true;
            } else if (c == '\n' || c == '\r') {
                if (c == '\r' && peek() == '\n') {
                    read();
                }
                line++;
                fields.add(field.toString());
                return fields;
            } else {
                if (fieldStart && (c == ' ' || c == '\t') && c != delimiter) {
                    // spaces before an opening quote don't stop it being quoted
                    field.append((char) c);
                    c = read();
                    if (c == '"' && field.toString().isBlank()) {
                        field.setLength(0);
                        quoted = true;
                        fieldStart = false;
                        c = read();
                    }
                    continue;
                }
                field.append((char) c);
                fieldStart = false;
            }
            c = read();
        }
    }

    @Override
    public void close() throws IOException {
        in.close();
    }
}
