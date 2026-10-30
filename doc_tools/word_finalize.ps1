param([string]$Src, [string]$Dst, [string]$Pdf)
$word = New-Object -ComObject Word.Application
$word.Visible = $false
$word.DisplayAlerts = 0
try {
    $doc = $word.Documents.Open($Src, $false, $false)
    # встроенные стили оглавления (wdStyleTOC1..3 = -20..-22): по левому краю, без красной строки
    $levels = @(@(-20, 0.0), @(-21, 0.5), @(-22, 1.0))
    foreach ($l in $levels) {
        $st = $doc.Styles.Item($l[0])
        $st.Font.Name = "Times New Roman"
        $st.Font.Size = 14
        $st.ParagraphFormat.Alignment = 0
        $st.ParagraphFormat.FirstLineIndent = 0
        $st.ParagraphFormat.LeftIndent = $word.CentimetersToPoints($l[1])
        $st.ParagraphFormat.SpaceAfter = 0
        $st.ParagraphFormat.LineSpacingRule = 1   # полуторный
    }
    $doc.Fields.Update() | Out-Null
    foreach ($toc in $doc.TablesOfContents) { $toc.Update() | Out-Null }
    $doc.Repaginate()
    foreach ($toc in $doc.TablesOfContents) { $toc.UpdatePageNumbers() | Out-Null }
    $doc.SaveAs2($Dst, 16)          # wdFormatXMLDocument
    $doc.ExportAsFixedFormat($Pdf, 17)   # wdExportFormatPDF
    "pages: " + $doc.ComputeStatistics(2)
    $doc.Close($false)
}
finally {
    $word.Quit()
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($word) | Out-Null
}
