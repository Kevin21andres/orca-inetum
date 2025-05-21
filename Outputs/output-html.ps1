using module "..\ORCA.psm1"

class html : ORCAOutput
{

    $OutputDirectory=$null
    $DisplayReport=$True
    $EmbedConfiguration=$false

    html()
    {
        $this.Name="HTML"
    }

    RunOutput($Checks,$Collection,[ORCAConfigLevel]$AssessmentLevel)
    {
    <#

        OUTPUT GENERATION / Header

    #>

    # Obtain the tenant domain and date for the report
    $TenantDomain = ($Collection["AcceptedDomains"] | Where-Object {$_.InitialDomain -eq $True}).DomainName
    $Tenant = $(($Collection["AcceptedDomains"] | Where-Object {$_.InitialDomain -eq $True}).DomainName -split '\.')[0]
    $ReportDate = $(Get-Date -format 'dd-MMM-yyyy HH:mm')

    # Summary Where-Object {$_.Completed -eq $true}
    $RecommendationCount = $($Checks | Where-Object {$_.Result -eq [ORCAResult]::Fail -and $_.Completed -eq $true}).Count
    $OKCount = $($Checks | Where-Object {$_.Result -eq [ORCAResult]::Pass -and $_.Completed -eq $true}).Count
    $InfoCount = $($Checks | Where-Object {$_.Result -eq [ORCAResult]::Informational -and $_.Completed -eq $true}).Count

    # Misc
    $ReportTitle = "Microsoft Defender for Office 365 Recommended Configuration Analyzer"
    $ReportSub1 = "Microsoft Defender for Office 365 Recommended inetum edition"
    $ReportSub2 = "Configuration Analyzer Report"
    # Area icons
    $AreaIcon = @{}
    $AreaIcon["Default"] = "fas fa-user-cog"
    $AreaIcon["Connectors"] = "fas fa-plug"
    $AreaIcon["Anti-Spam Policies"] = "fas fa-trash"
    $AreaIcon["Malware Filter Policy"] = "fas fa-biohazard"
    $AreaIcon["Zero Hour Autopurge"] = "fas fa-trash"
    $AreaIcon["DKIM"] = "fas fa-file-signature"
    $AreaIcon["Transport Rules"] = "fas fa-list"
    $AreaIcon["Transport Rules"] = "fas fa-list"

    # Embed checks as JSON in to HTML file at beginning for charting/historic purposes
    $MetaObject = New-Object -TypeName PSObject -Property @{
        Tenant=$Tenant
        TenantDomain=$TenantDomain
        ReportDate=$ReportDate
        Version=$($this.VersionCheck.Version.ToString())
        Config=$null
        EmbeddedConfiguration=$this.EmbedConfiguration
        Summary=New-Object -TypeName PSObject -Property @{
            Recommendation=$RecommendationCount
            OK=$OKCount
            InfoCount=$InfoCount
        }
        Checks=$Checks
    }

    if($this.EmbedConfiguration -eq $true)
    {
        # Write in to temp file to use clixml
        $TempFileXML = New-TemporaryFile

        # Create the temp path for zip
        $ZipTempLoc = New-TemporaryFile
        $ZipPath = $($ZipTempLoc.ToString()) + ".zip"

        # Export collection to XML file
        $Collection | Export-Clixml -Path $TempFileXML

        # Compress the XML to ZIP
        Compress-Archive -Path $TempFileXML -DestinationPath $ZipPath

        # Store in meta object, on Core use AsByteStream, on other use -Encoding byte
        if($global:PSVersionTable.PSEdition -eq "Core")
        {
            $MetaObject.Config = [convert]::ToBase64String((Get-Content -path $ZipPath -AsByteStream))
        }
        else 
        {
            $MetaObject.Config = [convert]::ToBase64String((Get-Content -path $ZipPath -Encoding byte))
        }
        
        $MetaObject.EmbeddedConfiguration = $true

        # Clean-up paths
        Remove-Item -Path $TempFileXML
        Remove-Item -Path $ZipTempLoc
        Remove-Item -Path $ZipPath
    }

    $EncodedText = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($MetaObject | ConvertTo-Json -Depth 100)))
    $output = "<!-- checkjson`n"
    $output += $($EncodedText)
    $output += "`nendcheckjson -->"

    # Get historic report info
    $HistoricData = $this.GetHistoricData($MetaObject,$Tenant)

    # Output start
    $output += "<!doctype html>
    <html lang='en'>
    <head>
        <!-- Required meta tags -->
        <meta charset='utf-8'>
        <meta name='viewport' content='width=device-width, initial-scale=1, shrink-to-fit=no'>

        <script src='https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.7/dist/umd/popper.min.js' integrity='sha384-zYPOMqeu1DAVkHiLqWBUTcbYfZ8osu1Nd6Z89ify25QV9guujx43ITvfi12/QExE' crossorigin='anonymous'></script>

        <link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css' rel='stylesheet' integrity='sha384-KK94CHFLLe+nY2dmCWGMq91rCGa5gtU4mk92HdvYe+M/SXH301p5ILy+dN9+nJOZ' crossorigin='anonymous'>
        <script src='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/js/bootstrap.bundle.min.js' integrity='sha384-ENjdO4Dr2bkBIFxQpeoTz1HIcje39Wm4jDKdf19U8gI4ddQ3GYNS7NTKfAdVQSZe' crossorigin='anonymous'></script>

        <script src='https://code.jquery.com/jquery-3.3.1.slim.min.js' integrity='sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo' crossorigin='anonymous'></script>
        
        <link rel='stylesheet' href='https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.11.2/css/all.min.css' crossorigin='anonymous'>
        <script src='https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.11.2/js/all.js'></script>

        <script src='https://cdn.jsdelivr.net/npm/chart.js'></script>
        <script src='https://cdn.jsdelivr.net/npm/moment@2.27.0'></script>
        <script src='https://cdn.jsdelivr.net/npm/chartjs-adapter-moment@0.1.1'></script>
        
        <style>
        .table-borderless td,
        .table-borderless th {
            border: 0;
        }
        .bd-callout {
            padding: 1rem;
            margin-top: 1rem;
            margin-bottom: 1rem;
            border: 1px solid #eee;
            border-left-width: .25rem;
            border-radius: .25rem
        }
        
        .bd-callout h4 {
            margin-top: 0;
            margin-bottom: .25rem
        }
        
        .bd-callout p:last-child {
            margin-bottom: 0
        }
        
        .bd-callout code {
            border-radius: .25rem
        }
        
        .bd-callout+.bd-callout {
            margin-top: -.25rem
        }
        
        .bd-callout-info {
            border-left-color: #5bc0de
        }
        
        .bd-callout-info h4 {
            color: #5bc0de
        }
        
        .bg-info{
            background-color: #107c10 !important /* He añadido este stylo para cambiar el color de la barra de recarga*/
        }

        .bg-success{
            background-color: #107c10 !important /* He añadido este stylo para cambiar el color de la barra de recarga*/
        }

        .bd-callout-warning {
            border-left-color: #fdb800 /* He cambiado el color al #fdb800 */
        }
        

        .bd-callout-warning h4 {
            color: #fdb800 /* He cambiado el color al #fdb800 */
        }
        
        .bd-callout-danger {
            border-left-color: #f04641 /* He cambiado el color */
        }
        
        .bd-callout-danger h4 {
            color: #f04641 /* He cambiado el color*/
        }

        .bd-callout-success {
            border-left-color: #00aa9b
        }
        .text-primary {
            color: #00aa9b !important
        }

        .navbar-custom { 
            background-color: #00aa9b;
            color: white; 
            padding-bottom: 10px;

            
        } 

        .text-bg-info {
            background-color: #00aa9b !important; /* He añadido este estilo para cambiar el color de la barra de recarga */
        }

        /* Modify brand and text color */ 
          
        .navbar-custom .navbar-brand, 
        .navbar-custom .navbar-text { 
            color: white; 
            padding-top: 70px;
            padding-bottom: 10px;

        } 
        body {
            font-family: verdana; !important
        }
        .star-cb-group {
            /* remove inline-block whitespace */
            font-size: 0;
            /* flip the order so we can use the + and ~ combinators */
            unicode-bidi: bidi-override;
            direction: rtl;
            /* the hidden clearer */
          }
          .star-cb-group * {
            font-size: 1rem;
          }
          .star-cb-group > input {
            display: none;
          }
          .star-cb-group > input + label {
            /* only enough room for the star */
            display: inline-block;
            overflow: hidden;
            text-indent: 9999px;
            width: 1.7em;
            white-space: nowrap;
            cursor: pointer;
          }
          .star-cb-group > input + label:before {
            display: inline-block;
            text-indent: -9999px;
            content: ""\2606"";
            font-size: 30px;
            color: #005494;
          }
          .star-cb-group > input:checked ~ label:before, .star-cb-group > input + label:hover ~ label:before, .star-cb-group > input + label:hover:before {
            content:""\2605"";
            color: #e52;
          font-size: 30px;
            text-shadow: 0 0 1px #333;
          }
          .star-cb-group > .star-cb-clear + label {
            text-indent: -9999px;
            width: .5em;
            margin-left: -.5em;
          }
          .star-cb-group > .star-cb-clear + label:before {
            width: .5em;
          }
          .star-cb-group:hover > input + label:before {
            content: ""\2606"";
            color: #005494;
          font-size: 30px;
            text-shadow: none;
          }
          .star-cb-group:hover > input + label:hover ~ label:before, .star-cb-group:hover > input + label:hover:before {
            content: ""\2605"";
            color: #e52;
          font-size: 30px;
            text-shadow: 0 0 1px #333;
          }         
        </style>
        <script>
            window.onload = function () {
                // Espera un momento a que cargue el contenido
                setTimeout(() => {
                    window.print();
                }, 500); // 0.5 segundos de retardo por seguridad
            };
        </script>

        <title>$($ReportTitle)</title>

    </head>
    <body class='app header-fixed bg-light'>

        <nav class='navbar  fixed-top navbar-custom p-3 border-bottom d-print-block'>
            <div class='container-fluid'>
                <div class='col-sm' style='text-align:left'>
                    <div class='row'>
                        <div class='col col-md-auto'><img src='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAV8AAABmCAYAAABst5JQAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAA+9pVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADw/eHBhY2tldCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkIj8+IDx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IkFkb2JlIFhNUCBDb3JlIDUuNi1jMTQ1IDc5LjE2MzQ5OSwgMjAxOC8wOC8xMy0xNjo0MDoyMiAgICAgICAgIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wTU09Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9tbS8iIHhtbG5zOnN0UmVmPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvc1R5cGUvUmVzb3VyY2VSZWYjIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtbG5zOmRjPSJodHRwOi8vcHVybC5vcmcvZGMvZWxlbWVudHMvMS4xLyIgeG1wTU06T3JpZ2luYWxEb2N1bWVudElEPSJ1dWlkOjVEMjA4OTI0OTNCRkRCMTE5MTRBODU5MEQzMTUwOEM4IiB4bXBNTTpEb2N1bWVudElEPSJ4bXAuZGlkOjQ4NkNBQzk5Q0Q5NjExRUE4NUI1ODA3RjM2NjNGMkIxIiB4bXBNTTpJbnN0YW5jZUlEPSJ4bXAuaWlkOjQ4NkNBQzk4Q0Q5NjExRUE4NUI1ODA3RjM2NjNGMkIxIiB4bXA6Q3JlYXRvclRvb2w9IkFkb2JlIElsbHVzdHJhdG9yIENTNiAoTWFjaW50b3NoKSI+IDx4bXBNTTpEZXJpdmVkRnJvbSBzdFJlZjppbnN0YW5jZUlEPSJ1dWlkOmE2MTJmNzJjLTI5OTEtNmI0Zi1hNjJlLWRiMjllMGIxOTNiNSIgc3RSZWY6ZG9jdW1lbnRJRD0ieG1wLmRpZDowNTgw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' alt='Inetum logo' style='width: 30%;' ></div>
                    </div>
                </div>
                <div class='col-sm' style='text-align:center'>
                    <strong>$($TenantDomain)</strong>
                </div>
                <div class='col-sm' style='text-align:right'>
                    $($ReportDate)
                </div>
            </div>
        </nav>  

            <div class='app-body p-3'>
            <main class='main'>
                <!-- Main content here -->
                <div class='container' style='padding-top:6em;'></div>
                <div class='card'>
                        
                <div class='card-body'>
                    <h2 class='card-title text-primary'><strong>$($ReportSub1)</strong></h2>
                    <p class='text-muted' style='margin-bottom: 1.2em;'>
                        Este documento, elaborado por <strong>Inetum</strong>, presenta un an&aacute;lisis t&eacute;cnico y estrat&eacute;gico del estado actual de configuraci&oacute;n y cumplimiento de su entorno Microsoft 365, 
                        con especial enfoque en la soluci&oacute;n Microsoft Defender for Office 365. Su objetivo principal es proporcionar una evaluaci&oacute;n precisa y fundamentada de la postura de seguridad de su organizaci&oacute;n, 
                        aline&aacute;ndose con las <strong>mejores pr&aacute;cticas recomendadas por Microsoft</strong> para entornos empresariales en constante evoluci&oacute;n.
                    </p>

                    <h2 class='card-title text-secondary' style='margin-top: -10px;'><strong>$($ReportSub2)</strong></h2>
                    <p class='text-muted'>
                        A lo largo del presente informe encontrar&aacute; una recopilaci&oacute;n exhaustiva de los principales hallazgos, riesgos potenciales y desviaciones respecto a la configuraci&oacute;n ideal, 
                        junto con recomendaciones pr&aacute;cticas y priorizadas para mitigar vulnerabilidades, fortalecer los controles de seguridad, 
                        y asegurar el cumplimiento de normativas y est&aacute;ndares de protecci&oacute;n de datos (como ISO 27001, ENS o RGPD, entre otros).
                    </p>
                    <p class='text-muted'>
                        Este an&aacute;lisis est&aacute; dise&ntilde;ado no solo para equipos t&eacute;cnicos, sino tambi&eacute;n para responsables de seguridad, cumplimiento y gesti&oacute;n de TI, 
                        permitiendo tomar decisiones informadas basadas en evidencias objetivas extra&iacute;das directamente desde el entorno del cliente.
                    </p>
                    <p class='text-muted'>
                        <strong>Inetum</strong> agradece la confianza depositada en nuestro equipo para acompa&ntilde;arles en el proceso de mejora continua y ciberseguridad de su organizaci&oacute;n.
                    </p>


                "

        <#

                OUTPUT GENERATION / Version Warning

        #>

        if($this.EmbedConfiguration)
        {
            $Output += "
            <div class='alert alert-warning pt-2' role='alert'>
                <p><strong>Embedded Configuration is present</strong></p>
                <p>This report has embedded configuration in it as ORCA was ran with the -EmbedConfiguration parameter. This allows anyone who holds this report file to view your configuration for the purpose of supporting your organisation, or as a snapshot of your configuration at a point in time. In order to read the configuration in this report, with the ORCA module installed, run Get-ORCAReportEmbeddedConfig -File <path to this .html file>.</p>
                <p>For those holding this report, treat this report file as confidential, and only send this report to people that you trust reading your configuration.</p>
            </div>" 
        }
    

                        $Output += "</div>
                </div>"

                        $Output += "</div>
                </div>"



    <#

        OUTPUT GENERATION / Summary cards

    #>

    $Output += "

                <div class='row p-3'>"

                if($InfoCount -gt 0)
                {
                    $Output += "
                    
                            <div class='col d-flex justify-content-center text-center'>
                                <div class='card text-white bg-secondary mb-3' style='width: 18em;'>
                                    <div class='card-header'><h6>Informativo</h6></div>
                                    <div class='card-body'>
                                    <h3>$($InfoCount)</h3>
                                    </div>
                                </div>
                            </div>
                    
                    "
                }

$Output +=        "<div class='col d-flex justify-content-center text-center'>
                    <div class='card text-white bg-warning mb-3' style='width: 18rem;'>
                        <div class='card-header'><h6>Recomendaciones</h6></div>
                        <div class='card-body'>
                        <h3>$($RecommendationCount)</h3>
                        </div>
                    </div>
                </div>

                <div class='col d-flex justify-content-center text-center'>
                    <div class='card text-white bg-success mb-3' style='width: 18rem;'>
                        <div class='card-header'><h6>OK</h6></div>
                        <div class='card-body'>
                        <h3>$($OKCount)</h3>
                        </div>
                    </div>
                </div>
            </div>"

    <#
    
                SURVEY OUTPUT
    
    #>


    <#
    
                OUTPUT GENERATION / Config Health Index

    #>

    $Output += "
    <div class='card m-3'>

        <div class='card-body'>
            <div class='row'>
                <div class='col-sm-4 text-center align-self-center'>

                    <div class='progress' style='height: 40px'>
                        <div class='progress-bar progress-bar-striped bg-info' role='progressbar' style='width: $($Collection["CHI"])%;' aria-valuenow='$($Collection["CHI"])' aria-valuemin='0' aria-valuemax='100'><h2>$($Collection["CHI"]) %</h2></div>
                    </div>
                
                </div>
                <div class='col-sm-8'>
                    <h6>&Iacute;ndice de estado de la configuraci&oacute;n</h6>                  
                    <p>El &Iacute;ndice de estado de la configuraci&oacute;n es un valor ponderado que representa la configuraci&oacute;n. No se tienen en cuenta todas las configuraciones, y algunas tienen mayor ponderaci&oacute;n que otras. </p>

                </div>
            </div>
                    
    </div>
  
    
    "

    <#
    
        OUTPUT GENERATION / Summary

    #>

    $Output += "
    <div class='card m-3'>
        <div class='card-header'>
            &Iacute;ndice
        </div>
        <div class='card-body'>"


    $Output += "<h5>Areas</h1>
            <table class='table table-borderless'>"
    ForEach($Area in ($Checks | Where-Object {$_.Completed -eq $true} | Group-Object Area))
    {

        $Pass = @($Area.Group | Where-Object {$_.Result -eq [ORCAResult]::Pass}).Count
        $Fail = @($Area.Group | Where-Object {$_.Result -eq [ORCAResult]::Fail}).Count
        $Info = @($Area.Group | Where-Object {$_.Result -eq [ORCAResult]::Informational}).Count

        $Icon = $AreaIcon[$Area.Name]
        If($Null -eq $Icon) { $Icon = $AreaIcon["Default"]}

        $Output += "
        <tr>
            <td width='20'><i class='$Icon'></i>
            <td><a href='`#$($Area.Name)'>$($Area.Name)</a></td>
            <td align='right'>
                <span class='badge text-bg-secondary' style='padding:15px;text-align:center;width:40px;"; if($Info -eq 0) { $output += "opacity: 0.1;" }; $output += "'>$($Info)</span>
                <span class='badge text-bg-warning' style='padding:15px;text-align:center;width:40px;"; if($Fail -eq 0) { $output += "opacity: 0.1;" }; $output += "'>$($Fail)</span>
                <span class='badge text-bg-success' style='padding:15px;text-align:center;width:40px;"; if($Pass -eq 0) { $output += "opacity: 0.1;" }; $output += "'>$($Pass)</span>
            </td>
        </tr>
        "
    }

    $Output+="</table>
        </div>
    </div>
    "

    <#
    
    Keys
    
    #>

    $Output += "
    <div class='card m-3'>
        <div class='card-header'>
            Leyenda
        </div>
        <div class='card-body'>
            <table class='table table-borderless'>

                <tr>
                    <td width='100'>
                        <div class='flex-row badge badge-pill text-bg-dark'>
                            <span style='vertical-align: middle;'>Desactivado</span>
                            <span class='fas fa-times-circle text-muted' style='vertical-align: middle;'></span>
                        </div>
                    </td>
                    <td>
                        La configuraci&oacute;n deshabilitada o las pol&iacute;ticas deshabilitadas no se aplicar&aacute;n debido a la deshabilitaci&oacute;n expl&iacute;cita de la pol&iacute;tica o configuraci&oacute;n.
                    </td>
                </tr>

                <tr>
                    <td width='100'>
                        <div class='flex-row badge badge-pill text-bg-secondary'>
                            <span style='vertical-align: middle;'>No aplica</span>
                            <span class='fas fa-times-circle text-muted' style='vertical-align: middle;'></span>
                        </div>
                    </td>
                    <td>
                        Estas pol&iacute;ticas o configuraciones no se aplican debido a su precedencia o a sus excepciones. Un ejemplo es una pol&iacute;tica predeterminada, donde existe una pol&iacute;tica predefinida que se aplica sin excepciones.                    
                    </td>
                </tr>

                <tr>
                    <td width='100'>
                        <div class='flex-row badge badge-pill text-bg-light'>
                            <span style='vertical-align: middle;'>Solo Lectura</span>
                            <span class='fas fa-lock text-muted' style='vertical-align: middle;'></span>
                        </div>
                    </td>
                    <td>
                        Las pol&iacute;ticas de solo lectura no se pueden modificar. Si contienen configuraciones no deseadas, aplique una pol&iacute;tica de orden superior para que no se apliquen.
                    </td>
                </tr>

                <tr>
                    <td width='100'>
                        <div class='flex-row badge badge-pill text-bg-info'>
                            <span style='vertical-align: middle;'>Est&aacute;ndar preestablecido/estricto</span>
                        </div>
                    </td>
                    <td>
                        Las pol&iacute;ticas preestablecidas proporcionan configuraciones controladas por Microsoft y configuradas en un nivel espec&iacute;fico de controles (Est&aacute;ndar o Estricto); la mayor&iacute;a de las configuraciones suelen ser de solo lectura.
                    </td>
                </tr>

                <tr>
                    <td width='100'>
                        <div class='flex-row badge badge-pill text-bg-info'>
                            <span style='vertical-align: middle;'>Pol&iacute;tica de protecci&oacute;n integrada</span>
                        </div>
                    </td>
                    <td>
                        Las pol&iacute;ticas integradas se aplican en ausencia de otras pol&iacute;ticas; la mayor&iacute;a de las configuraciones suelen ser de solo lectura.
                    </td>
                </tr>

            </table>

        </div>
    </div>"

    <#

        OUTPUT GENERATION / Zones

    #>

    ForEach ($Area in ($Checks | Where-Object {$_.Completed -eq $True} | Group-Object Area)) 
    {

        # Write the top of the card
        $Output += "
        <div class='card m-3'>
            <div class='card-header'>
            <a name='$($Area.Name)'>$($Area.Name)</a>
            </div>
            <div class='card-body'>"

        # Each check
        ForEach ($Check in ($Area.Group | Sort-Object Result -Descending)) 
        {

            $Output += "        
                <h5>$($Check.Name)</h5>"

                    If($Check.Result -eq [ORCAResult]::Pass) 
                    {
                        $CalloutType = "bd-callout-success"
                        $BadgeType = "text-bg-success"
                        $BadgeName = "OK"
                        $Icon = "fas fa-thumbs-up"
                        $Title = $Check.PassText
                    } 
                    ElseIf($Check.Result -eq [ORCAResult]::Informational) 
                    {
                        $CalloutType = "bd-callout-secondary"
                        $BadgeType = "text-bg-secondary"
                        $BadgeName = "Informational"
                        $Icon = "fas fa-thumbs-up"
                        $Title = $Check.FailRecommendation
                    }
                    Else 
                    {
                        $CalloutType = "bd-callout-warning"
                        $BadgeType = "text-bg-warning"
                        $BadgeName = "Improvement"
                        $Icon = "fas fa-thumbs-down"
                        $Title = $Check.FailRecommendation
                    }

#<span class="badge text-bg-primary">Primary</span>

                    $Output += "  
                    
                        <div class='bd-callout $($CalloutType) b-t-1 b-r-1 b-b-1 p-3'>
                            <div class='container-fluid'>
                                <div class='row'>
                                    <div class='col-1'><i class='$($Icon)'></i></div>
                                    <div class='col-8'><h5>$($Title)</h5></div>
                                    <div class='col' style='text-align:right'><h5><span class='badge $($BadgeType)'>$($BadgeName)</span></h5></div>
                                </div>"


                        if($Check.CheckFailed)
                        {
                                $Output +="
                                <div class='row p-3'>
                                    <div class='alert alert-danger' role='alert'>
                                    This check failed to run.  $($Check.CheckFailureReason)
                                    </div>
                                </div>"
                        }

                        if($Check.Importance) {

                                $Output +="
                                <div class='row p-3'>
                                    <div><p>$($Check.Importance)</p></div>
                                </div>"

                        }

                        If($Check.ExpandResults -eq $True) {

                            # We should expand the results by showing a table of Config Data and Items
                            $Output +="<h6>Effected objects</h6>
                            <div class='row pl-2 pt-3'>
                                <table class='table'>
                                    <thead class='border-bottom'>
                                        <tr>"

                            If($Check.CheckType -eq [CheckType]::ObjectPropertyValue)
                            {
                                # Object, property, value checks need three columns
                                $Output +="
                                <th>$($Check.ObjectType)</th>
                                <th>$($Check.ItemName)</th>
                                <th>$($Check.DataType)</th>
                                "    
                            }
                            Else
                            {
                                $Output +="
                                <th>$($Check.ItemName)</th>
                                <th>$($Check.DataType)</th>
                                "     
                            }

                            $Output +="
                                            <th style='width:100px'></th>
                                        </tr>
                                    </thead>
                                    <tbody>
                            "

                            ForEach($o in $($Check.Config | Sort-Object Level))
                            {

                                $chiicon = ""
                                $chipill = ""
                                $chipts = [int]$($Check.ChiValue)

                                # Determine which to use based on AssessmentLevel
                                [ORCAResult]$AssessedResult = $o.ResultStandard

                                if($AssessmentLevel -eq [ORCAConfigLevel]::Strict)
                                {
                                    [ORCAResult]$AssessedResult = $o.ResultStrict
                                }
                                
                                if($AssessedResult -eq [ORCAResult]::Pass) 
                                {
                                    $oicon="fas fa-check-circle text-success"
                                    
                                    $LevelText = $o.Level.ToString()

                                    if($Check.ChiValue -ne [ORCACHI]::NotRated)
                                    {
                                        $chiicon = "fas fa-plus"
                                        $chipill = "text-bg-success"
                                    }
                                }
                                ElseIf($AssessedResult -eq [ORCAResult]::Informational) 
                                {
                                    $oicon="fas fa-info-circle text-muted"
                                    $LevelText = "Informativo"
                                }
                                Else
                                {
                                    $oicon="fas fa-times-circle text-danger"
                                    $LevelText = "No recomendado"

                                    if($Check.ChiValue -ne [ORCACHI]::NotRated)
                                    {
                                        $chiicon = "fas fa-minus"
                                        $chipill = "text-bg-danger"
                                    }
                                }

                                $Output += "
                                <tr>
                                "

                                # Multi line ConfigItem or ConfigData
                                If($o.ConfigItem -is [array] -or $o.ConfigItem -is [System.Collections.ArrayList])
                                {
                                    $ConfigItem = $o.ConfigItem -join "<br>"
                                }
                                else 
                                {
                                    $ConfigItem = $o.ConfigItem
                                }
                                If($o.ConfigData -is [array] -or $o.ConfigData -is [System.Collections.ArrayList])
                                {
                                    $ConfigData = $o.ConfigData -join "<br>"
                                }
                                else 
                                {
                                    $ConfigData = $o.ConfigData
                                }

                                $PolicyPills = "";

                                if($null -ne $o.ConfigPolicyGuid)
                                {
                                    # Get policy object
                                    $Policy = $Collection["PolicyStates"][$o.ConfigPolicyGuid]

                                    if($Policy.Preset)
                                    {
                                        $PolicyPills += "
                                            <div class='flex-row badge badge-pill text-bg-info'>
                                                <span style='vertical-align: middle;'>Preestablecido($($Policy.PresetLevel.ToString()))</span>
                                            </div>"
                                    }

                                    if($Policy.BuiltIn)
                                    {
                                        $PolicyPills += "
                                            <div class='flex-row badge badge-pill text-bg-info'>
                                                <span style='vertical-align: middle;'>Pol&iacute;tica de protecci&oacute;n integrada</span>
                                            </div>"
                                    }

                                }

                                If($Check.CheckType -eq [CheckType]::ObjectPropertyValue)
                                {
                                    # Object, property, value checks need three columns
                                    $Output += "<td>$($o.Object)"

                                    if($o.ConfigDisabled -eq $true)
                                    {
                                        $Output += "
                                                <div class='flex-row badge badge-pill text-bg-dark'>
                                                    <span style='vertical-align: middle;'>Desactivado</span>
                                                    <span class='fas fa-times-circle text-muted' style='vertical-align: middle;'></span>
                                                </div>"
                                    }

                                    if($o.ConfigWontApply -eq $true)
                                    {
                                        $Output += "
                                                <div class='flex-row badge badge-pill text-bg-secondary'>
                                                    <span style='vertical-align: middle;'>no se aplica</span>
                                                    <span class='fas fa-times-circle text-muted' style='vertical-align: middle;'></span>
                                                </div>"
                                    }

                                    if($o.ConfigReadonly -eq $true)
                                    {
                                        $Output += "
                                                <div class='flex-row badge badge-pill text-bg-light'>
                                                    <span style='vertical-align: middle;'>Solo Lectura</span>
                                                    <span class='fas fa-lock text-muted' style='vertical-align: middle;'></span>
                                                </div>"
                                    }
                                    
                                    $Output += $PolicyPills
                                    
                                    $Output += "</td>"
                                        
                                    $Output += "<td>$($ConfigItem)</td>
                                        <td style='word-wrap: break-word;min-width: 50px;max-width: 350px;'>$($ConfigData)</td>
                                    "
                                }
                                Else 
                                {
                                    $Output += "<td>$($ConfigItem)"

                                    if($o.ConfigDisabled -eq $true)
                                    {
                                        $Output += "
                                                <div class='flex-row badge badge-pill text-bg-dark'>
                                                    <span style='vertical-align: middle;'>Desactivado</span>
                                                    <span class='fas fa-times-circle text-muted' style='vertical-align: middle;'></span>
                                                </div>"
                                    }

                                    if($o.ConfigWontApply -eq $true)
                                    {
                                        $Output += "
                                                <div class='flex-row badge badge-pill text-bg-secondary'>
                                                    <span style='vertical-align: middle;'>no se aplica</span>
                                                    <span class='fas fa-times-circle text-muted' style='vertical-align: middle;'></span>
                                                </div>"
                                    }

                                    if($o.ConfigReadonly -eq $true)
                                    {
                                        $Output += "
                                                <div class='flex-row badge badge-pill text-bg-light'>
                                                    <span style='vertical-align: middle;'>Solo Lectura</span>
                                                    <span class='fas fa-lock text-muted' style='vertical-align: middle;'></span>
                                                </div>"
                                    }

                                    $Output += $PolicyPills

                                    $Output += "</td>"

                                    $Output += "
                                        <td>$($ConfigData)</td>
                                    "
                                }

  
                                $Output += "
                                    <td style='text-align:right'>

                                    <div class='d-flex justify-content-end'>
                                "

                                if($($o.InfoText) -match "Esta es una pol&iacute;tica predeterminada/integrada")
                                {
                                    $Output += "
                                    <div class='flex-row badge badge-pill text-bg-light'>
                                        <span style='vertical-align: middle;'>$($LevelText)</span>
                                        <span class='$($oicon)' style='vertical-align: middle;'></span>
                                    "
                                    
                                    $Output += "<p style='margin-top:5px;color:#005494;'><abbr title='$($o.InfoText)'><u>More Info</u></abbr></p></div>"
                                    
                                }
                                elseif($($o.InfoText) -match "La pol&iacute;tica no está habilitada y no se aplicará.")
                                {
                                    $Output += "
                                    <div class='flex-row badge badge-pill text-bg-light'>
                                        <span style='vertical-align: middle;'>$($LevelText)</span>
                                        <span class='$($oicon)' style='vertical-align: middle;'></span>
                                    "
                                    $Output += "<p style='margin-top:5px;color:#005494;'><abbr title='$($o.InfoText)'><u>More Info</u></abbr></p></div>"                             
                                    
                                }
                                elseif($o.Level -eq [ORCAConfigLevel]::Informational)
                                {
                                    $Output += "
                                    <div class='flex-row badge badge-pill text-bg-light'>
                                        <span style='vertical-align: middle;'>$($LevelText)</span>
                                        <span class='$($oicon)' style='vertical-align: middle;'></span>
                                    "
                                    $Output += "<p style='margin-top:5px;color:#005494;'><abbr title='$($o.InfoText)'><u>More Info</u></abbr></p></div>"
                              
                                }
                                else
                                {
                                    $Output += "
                                                <div class='flex-row badge badge-pill text-bg-light'>
                                                    <span style='vertical-align: middle;'>$($LevelText)</span>
                                                    <span class='$($oicon)' style='vertical-align: middle;'></span>
                                                </div>"
                                

                                if($Check.ChiValue -ne [ORCACHI]::NotRated -and $o.Level -ne [ORCAConfigLevel]::Informational)
                                {
                                    $Output += "
                                                <div class='flex-row badge badge-pill $($chipill)'>
                                                    <span class='$($chiicon)' style='vertical-align: middle;'></span>
                                                    <span style='vertical-align: middle;'>$($chipts)</span>     
                                                </div>
                                    "
                                }            
                            }
                                $Output += "

                                    </div>

                                    </td>
                                </tr>
                                "
                            }

                            $Output +="
                                    </tbody>
                                </table>"
                                


                            $Output +="
                            </div>"

                        }

                        # If any links exist
                        If($Check.Links)
                        {
                            $Output += "
                            <table>"
                            ForEach($Link in $Check.Links.Keys) {
                                $Output += "
                                <tr>
                                <td style='width:40px'><i class='fas fa-external-link-alt'></i></td>
                                <td><a href='$($Check.Links[$Link])'>$Link</a></td>
                                <tr>
                                "
                            }
                            $Output += "
                            </table>
                            "
                        }

                        $Output += "
                            </div>
                        </div>  "
        }            

        # End the card
        $Output+=   "
            </div>
        </div>"

    }
    <#

        OUTPUT GENERATION / Footer

    #>

    $Output += "
            </main>
            </div>
        </body>"

    <#
    
        CHART GENERATION
    
    #>

    $Output += "<script>

    const ctx = document.getElementById('chartOverview');"

    $Output += $this.getChartDataOverview($HistoricData)

    $Output += "let chart = new Chart(ctx, {
        type: 'line',
        data: data,
        
        options: {
          scales: {
            x: {
              type: 'time',
              time: {
                unit: 'day'
                }
            }
          },
        },
      });
  </script>"

    $Output += "</html>"


        # Write to file

        $OutputDir = $this.GetOutputDir();

        $ReportFileName = "Inetum-$($tenant)-$(Get-Date -Format 'yyyyMMddHHmm').html"

        $OutputFile = "$OutputDir\$ReportFileName"

        $Output | Out-File -FilePath $OutputFile

        If($this.DisplayReport)
        {
            
            Invoke-Expression "&'$OutputFile'"
        }

        $this.Completed = $True
        $this.Result = $OutputFile

    }

    [string]GetOutputDir()
    {
        if($null -eq $this.OutputDirectory)
        {
            return $this.DefaultOutputDirectory
        }
        else 
        {
            return $this.OutputDirectory
        }
    }

    [string]getChartDataOverview($HistoricData)
    {

        $Output = "";
        $Output += "const data = {"
        $Output += "labels: ["
        # Build labels
        foreach($dataSet in $HistoricData)
        {
            $Output += "new Date('$($dataSet.ReportDate)'),"
        }

        # build dataset Recommendation OK InfoCount
        $Output += "],
        datasets: [{
            label: 'Info',
            borderColor: '#adb5bd',
            backgroundColor: '#adb5bd',
            data: ["

            foreach($dataSet in $HistoricData)
            {
                $Output += "$($dataSet.Summary.InfoCount),"
            }

            $Output += "],
          },
          {
            label: 'Recommendation',
            borderColor: '#ffc107',
            backgroundColor: '#ffc107',
            data: ["

            foreach($dataSet in $HistoricData)
            {
                $Output += "$($dataSet.Summary.Recommendation),"
            }

            $Output += "],
          },
          {
            label: 'OK',
            borderColor: '#198754',
            backgroundColor: '#198754',
            data: ["

            foreach($dataSet in $HistoricData)
            {
                $Output += "$($dataSet.Summary.OK),"
            }

            $Output += "],
          }],
        };"
        return $Output += "`n"
    }

    [Object[]]GetHistoricData($Current,$Tenant)
    {
        $HistoricData = @($Current)


        # Get reports in outputdirectory
        try {

            $Path = $($this.GetOutputDir() + "\ORCA-$($Tenant)-*.html");
    
            $MatchingReports = Get-ChildItem $Path
            ForEach($MatchReport in $MatchingReports)
            {
                # Get the first line
                $FirstLines = Get-Content $MatchReport -First 2
                if($FirstLines[0] -like "<!-- checkjson*")
                {
                    # Get the underlying object
                    $DecodedText = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($FirstLines[1]))
                    $Object = ConvertFrom-Json $DecodedText

                    if($Object.Tenant -eq $Tenant)
                    {
                        Write-Host "$(Get-Date) Output - HTML - Got historic data for tenant $($Tenant) in $($MatchReport.FullName)"
                        $HistoricData += $Object
                    }
                }
            }
        }
        catch {
            <#Do this if a terminating exception happens#>
        }

        return $HistoricData;
    }

}