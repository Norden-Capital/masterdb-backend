package ca.nordencapital.masterdb.lists.imports;

import ca.nordencapital.masterdb.validation.engine.EmailAddress;

import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Looks at the first rows of a file and guesses how to read it: the field
 * separator, whether the first row is a header, and which column holds the
 * email address. The user sees the guess with a few rows and can change the
 * header and the column before the import starts.
 */
public final class ColumnGuess {

    /** Separators tried, in order of preference on a tie. */
    static final char[] DELIMITERS = {',', ';', '\t', '|'};
    private static final Pattern EMAIL_HEADER = Pattern.compile("^(e[-_ ]?mail|courriel|mail)([-_ ]?(address|adresse|"
            + "addr))?$");

    private ColumnGuess() {
    }

    /**
     * @param delimiter   0 = one column
     * @param columns     header cells (blank → "Column N"), or "Column 1…N"
     * @param emailColumn 0-based
     * @param emailsFound valid addresses in the email column of the sample rows (header excluded)
     */
    public record Guess(char delimiter, boolean hasHeader, int emailColumn, List<String> columns,
            List<List<String>> rows, int emailsFound) {
    }

    /** {@code sample}: the start of the file (whole records only matter; a cut last line is ignored). */
    public static Guess of(String sample, boolean complete) {
        char best = 0;
        int bestScore = 0;
        for (char d : DELIMITERS) {
            int score = consistency(records(sample, d, complete));
            if (score > bestScore) {
                best = d;
                bestScore = score;
            }
        }
        List<List<String>> rows = records(sample, best, complete);
        rows.removeIf(r -> r.size() == 1 && r.getFirst().isBlank());
        int width = rows.stream().mapToInt(List::size).max().orElse(1);
        boolean header = !rows.isEmpty() && rows.getFirst().stream().noneMatch(ColumnGuess::isEmail)
                && rows.stream().skip(1).anyMatch(r -> r.stream().anyMatch(ColumnGuess::isEmail));
        int column = -1;
        if (header) {
            List<String> h = rows.getFirst();
            for (int i = 0; i < h.size() && column < 0; i++) {
                if (EMAIL_HEADER.matcher(h.get(i).trim().toLowerCase(Locale.ROOT)).matches()) {
                    column = i;
                }
            }
        }
        if (column < 0) {
            column = mostEmails(rows, header, width);
        }
        List<String> columns = names(header ? rows.getFirst() : List.of(), width);
        return new Guess(best, header, column, columns, rows, emails(rows, header, column));
    }

    /** Column names: the header's cells, or "Column N" where it has none. */
    public static List<String> names(List<String> header, int width) {
        List<String> out = new ArrayList<>();
        for (int i = 0; i < Math.max(width, header.size()); i++) {
            String h = i < header.size() ? header.get(i).trim() : "";
            out.add(h.isEmpty() ? "Column " + (i + 1) : h.length() > 100 ? h.substring(0, 100) : h);
        }
        return out;
    }

    /** Valid addresses found in {@code column} of the rows. */
    public static int emails(List<List<String>> rows, boolean header, int column) {
        int n = 0;
        for (int i = header ? 1 : 0; i < rows.size(); i++) {
            List<String> r = rows.get(i);
            if (column < r.size() && isEmail(r.get(column))) {
                n++;
            }
        }
        return n;
    }

    private static int mostEmails(List<List<String>> rows, boolean header, int width) {
        int best = 0;
        int bestCount = 0;
        for (int c = 0; c < width; c++) {
            int n = emails(rows, header, c);
            if (n > bestCount) {
                best = c;
                bestCount = n;
            }
        }
        return best;
    }

    /** Rows with the most common field count (above 1); 0 when no row splits. */
    private static int consistency(List<List<String>> rows) {
        Map<Integer, Integer> widths = new HashMap<>();
        for (List<String> r : rows) {
            if (r.size() > 1) {
                widths.merge(r.size(), 1, Integer::sum);
            }
        }
        return widths.values().stream().mapToInt(Integer::intValue).max().orElse(0);
    }

    static List<List<String>> records(String sample, char delimiter, boolean complete) {
        List<List<String>> out = new ArrayList<>();
        String text = sample;
        if (!complete) {
            int cut = Math.max(text.lastIndexOf('\n'), text.lastIndexOf('\r'));
            text = cut < 0 ? text : text.substring(0, cut);
        }
        try (CsvReader r = new CsvReader(new StringReader(text), delimiter, Math.max(1, text.length() + 1))) {
            List<String> rec;
            while ((rec = r.next()) != null && out.size() < 200) {
                out.add(rec);
            }
        } catch (IOException e) {
            // an unclosed quote in the sample: keep what was read
        }
        return out;
    }

    static boolean isEmail(String cell) {
        return cell != null && cell.indexOf('@') > 0 && EmailAddress.parse(cell).isPresent();
    }
}
