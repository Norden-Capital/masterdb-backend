package ca.nordencapital.masterdb.lists.imports;

import ca.nordencapital.masterdb.web.error.BadRequestException;
import org.junit.jupiter.api.Test;

import java.io.StringReader;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The pieces of an import that need no database: CSV reading, the column guess, Drive links. */
class ListParsingTest {

    static List<List<String>> read(String text, char delimiter, int max) throws Exception {
        List<List<String>> out = new ArrayList<>();
        try (CsvReader r = new CsvReader(new StringReader(text), delimiter, max)) {
            List<String> rec;
            while ((rec = r.next()) != null) {
                out.add(rec);
            }
        }
        return out;
    }

    @Test
    void csvHandlesQuotesLineEndsAndTheByteOrderMark() throws Exception {
        assertThat(read("﻿a,b\r\n\"x, y\",\"say \"\"hi\"\"\"\r\"multi\nline\",z\nlast", ',', 1000))
                .containsExactly(List.of("a", "b"), List.of("x, y", "say \"hi\""), List.of("multi\nline", "z"),
                        List.of("last"));
        assertThat(read("one@x.test\n\ntwo@x.test", (char) 0, 1000)).containsExactly(List.of("one@x.test"),
                List.of(""), List.of("two@x.test"));
        assertThatThrownBy(() -> read("a\n\"never closed " + "x".repeat(100), ',', 50))
                .isInstanceOf(CsvReader.CsvException.class).hasMessageContaining("Line 2")
                .hasMessageContaining("quote");
    }

    @Test
    void theGuessFindsSeparatorHeaderAndEmailColumn() {
        ColumnGuess.Guess g = ColumnGuess.of("first;last;Email Address\nAnn;Lee;ann@x.test\nBo;Ng;bo@x.test\n", true);
        assertThat(g.delimiter()).isEqualTo(';');
        assertThat(g.hasHeader()).isTrue();
        assertThat(g.emailColumn()).isEqualTo(2);
        assertThat(g.columns()).containsExactly("first", "last", "Email Address");

        ColumnGuess.Guess noHeader = ColumnGuess.of("Ann\tann@x.test\nBo\tbo@x.test\n", true);
        assertThat(noHeader.delimiter()).isEqualTo('\t');
        assertThat(noHeader.hasHeader()).isFalse();
        assertThat(noHeader.emailColumn()).isEqualTo(1);
        assertThat(noHeader.columns()).containsExactly("Column 1", "Column 2");

        ColumnGuess.Guess plain = ColumnGuess.of("email\na@x.test\nb@x.test\nc@x.te", false);
        assertThat(plain.delimiter()).isEqualTo((char) 0);
        assertThat(plain.hasHeader()).isTrue();
        assertThat(plain.rows()).hasSize(3); // the cut last line is left out
    }

    @Test
    void driveLinksBecomeTheirDownloadAddress() {
        assertThat(DriveLink.parse("https://drive.google.com/file/d/1AbCdEfGhIjK/view?usp=sharing").download())
                .isEqualTo(URI.create("https://drive.google.com/uc?export=download&id=1AbCdEfGhIjK"));
        assertThat(DriveLink.parse("https://drive.google.com/uc?export=download&id=1AbCdEfGhIjK").download())
                .isEqualTo(URI.create("https://drive.google.com/uc?export=download&id=1AbCdEfGhIjK"));
        assertThat(DriveLink.parse("https://docs.google.com/spreadsheets/d/1AbCdEfGhIjK/edit#gid=0").download())
                .isEqualTo(URI.create("https://docs.google.com/spreadsheets/d/1AbCdEfGhIjK/export?format=csv"));
        assertThat(DriveLink.parse("https://docs.google.com/document/u/0/d/1AbCdEfGhIjK/edit").kind())
                .isEqualTo(DriveLink.Kind.DOC);
        assertThatThrownBy(() -> DriveLink.parse("https://docs.google.com/presentation/d/1AbCdEfGhIjK/edit"))
                .isInstanceOf(BadRequestException.class);
    }

    @Test
    void onlyHttpsToGoogleDownloadHostsIsAllowed() {
        assertThat(DriveLink.allowedHop(URI.create("https://drive.usercontent.google.com/download?id=x"))).isTrue();
        assertThat(DriveLink.allowedHop(URI.create("https://doc-0s-9c-docs.googleusercontent.com/docs/x"))).isTrue();
        assertThat(DriveLink.allowedHop(URI.create("http://drive.google.com/uc"))).isFalse();
        assertThat(DriveLink.allowedHop(URI.create("https://accounts.google.com/ServiceLogin"))).isFalse();
        assertThat(DriveLink.allowedHop(URI.create("https://localhost/x"))).isFalse();
        assertThat(DriveLink.allowedHop(URI.create("https://a.googleusercontent.com.evil.test/x"))).isFalse();
        assertThat(DriveLink.allowedHop(URI.create("https://drive.google.com:444/x"))).isFalse();
    }
}
