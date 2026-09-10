using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Xml;

namespace UnifiedGateway.Services;

/// <summary>One cell: either a number or a string, so Excel gets the right type.</summary>
public readonly record struct XlsxCell(string? Text, double? Number)
{
    public static XlsxCell Str(string? value) => new(value ?? string.Empty, null);
    public static XlsxCell Num(decimal value) => new(null, (double)value);
    public static XlsxCell Num(long value) => new(null, value);
}

/// <summary>
/// Writes a minimal single-sheet .xlsx.
///
/// An .xlsx is a zip of XML parts, so this needs no third-party package — worth the ~100
/// lines to avoid a dependency, and it means finance opens a real workbook with real numeric
/// cells rather than a CSV that Excel re-guesses on every import.
/// </summary>
public static class XlsxWriter
{
    public static byte[] Write(string sheetName, IReadOnlyList<string> headers, IReadOnlyList<XlsxCell[]> rows)
    {
        using var buffer = new MemoryStream();

        using (var archive = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            AddEntry(archive, "[Content_Types].xml", ContentTypes());
            AddEntry(archive, "_rels/.rels", RootRelationships());
            AddEntry(archive, "xl/workbook.xml", Workbook(sheetName));
            AddEntry(archive, "xl/_rels/workbook.xml.rels", WorkbookRelationships());
            AddEntry(archive, "xl/styles.xml", Styles());
            AddEntry(archive, "xl/worksheets/sheet1.xml", Sheet(headers, rows));
        }

        return buffer.ToArray();
    }

    private static void AddEntry(ZipArchive archive, string path, string content)
    {
        var entry = archive.CreateEntry(path, CompressionLevel.Optimal);
        using var stream = entry.Open();
        using var writer = new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        writer.Write(content);
    }

    private static string ContentTypes() =>
        """
        <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
          <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
          <Default Extension="xml" ContentType="application/xml"/>
          <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
          <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
          <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
        </Types>
        """;

    private static string RootRelationships() =>
        """
        <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
          <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
        </Relationships>
        """;

    private static string Workbook(string sheetName) =>
        $"""
        <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
                  xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
          <sheets><sheet name="{Escape(SafeSheetName(sheetName))}" sheetId="1" r:id="rId1"/></sheets>
        </workbook>
        """;

    private static string WorkbookRelationships() =>
        """
        <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
          <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
          <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
        </Relationships>
        """;

    /// <summary>Two styles: index 0 plain, index 1 bold for the header row.</summary>
    private static string Styles() =>
        """
        <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
          <fonts count="2">
            <font><sz val="11"/><name val="Calibri"/></font>
            <font><b/><sz val="11"/><name val="Calibri"/></font>
          </fonts>
          <fills count="1"><fill><patternFill patternType="none"/></fill></fills>
          <borders count="1"><border/></borders>
          <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
          <cellXfs count="2">
            <xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
            <xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/>
          </cellXfs>
        </styleSheet>
        """;

    private static string Sheet(IReadOnlyList<string> headers, IReadOnlyList<XlsxCell[]> rows)
    {
        var sb = new StringBuilder();
        sb.Append("""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>""");
        sb.Append("""<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>""");

        sb.Append("""<row r="1">""");
        for (var c = 0; c < headers.Count; c++)
        {
            sb.Append($"""<c r="{Reference(c, 1)}" s="1" t="inlineStr"><is><t>{Escape(headers[c])}</t></is></c>""");
        }
        sb.Append("</row>");

        for (var r = 0; r < rows.Count; r++)
        {
            var rowNumber = r + 2;
            sb.Append($"""<row r="{rowNumber}">""");

            var cells = rows[r];
            for (var c = 0; c < cells.Length; c++)
            {
                var reference = Reference(c, rowNumber);
                var cell = cells[c];

                if (cell.Number.HasValue)
                {
                    var value = cell.Number.Value.ToString("R", CultureInfo.InvariantCulture);
                    sb.Append($"""<c r="{reference}"><v>{value}</v></c>""");
                }
                else
                {
                    sb.Append($"""<c r="{reference}" t="inlineStr"><is><t>{Escape(cell.Text)}</t></is></c>""");
                }
            }

            sb.Append("</row>");
        }

        sb.Append("</sheetData></worksheet>");
        return sb.ToString();
    }

    /// <summary>Turns a zero-based column index and 1-based row into an A1 reference.</summary>
    private static string Reference(int columnIndex, int rowNumber)
    {
        var column = string.Empty;
        var index = columnIndex;

        do
        {
            column = (char)('A' + index % 26) + column;
            index = index / 26 - 1;
        }
        while (index >= 0);

        return column + rowNumber.ToString(CultureInfo.InvariantCulture);
    }

    /// <summary>Excel rejects these characters in a sheet name, and caps it at 31 chars.</summary>
    private static string SafeSheetName(string name)
    {
        var cleaned = new string(name.Where(c => !"[]:*?/\\".Contains(c)).ToArray()).Trim();
        if (cleaned.Length == 0) cleaned = "Sheet1";
        return cleaned.Length > 31 ? cleaned[..31] : cleaned;
    }

    private static string Escape(string? value) =>
        string.IsNullOrEmpty(value) ? string.Empty : XmlEscape(value);

    private static string XmlEscape(string value)
    {
        var sb = new StringBuilder(value.Length);

        foreach (var ch in value)
        {
            // Control characters are not legal in XML 1.0 and make the workbook unopenable.
            if (XmlConvert.IsXmlChar(ch) is false)
            {
                continue;
            }

            sb.Append(ch switch
            {
                '<' => "&lt;",
                '>' => "&gt;",
                '&' => "&amp;",
                '"' => "&quot;",
                '\'' => "&apos;",
                _ => ch.ToString()
            });
        }

        return sb.ToString();
    }
}
