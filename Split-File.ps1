function Split-File
{
    
    param
    (
        [Parameter(Mandatory)]
        [String]
        $Path,

        [Int32]
        $PartSizeBytes = 1GB
    )

    try
    {
        # get the path parts to construct the individual part
        # file names:
        $fullBaseName = [IO.Path]::GetFileName($Path)
        $baseName = [IO.Path]::GetFileNameWithoutExtension($Path)
        $parentFolder = [IO.Path]::GetDirectoryName($Path)
        $extension = [IO.Path]::GetExtension($Path)

        # get the original file size and calculate the
        # number of required parts:
        $originalFile = New-Object System.IO.FileInfo($Path)
        $totalChunks = [int]($originalFile.Length / $PartSizeBytes) + 1
        $digitCount = [int][Math]::Log10($totalChunks) + 1

        # read the original file and split into chunks:
        $reader = [IO.File]::OpenRead($Path)
        $count = 0
        $buffer = New-Object Byte[] $PartSizeBytes
        $moreData = $true

        # read chunks until there is no more data
        while($moreData)
        {
            # read a chunk
            $bytesRead = $reader.Read($buffer, 0, $buffer.Length)
            # create the filename for the chunk file
            $chunkFileName = "$parentFolder\$fullBaseName.{0:D$digitCount}.part" -f $count
            Write-Verbose "saving to $chunkFileName..."
            $output = $buffer

            # did we read less than the expected bytes?
            if ($bytesRead -ne $buffer.Length)
            {
                # yes, so there is no more data
                $moreData = $false
                # shrink the output array to the number of bytes
                # actually read:
                $output = New-Object Byte[] $bytesRead
                [Array]::Copy($buffer, $output, $bytesRead)
            }
            # save the read bytes in a new part file
            [IO.File]::WriteAllBytes($chunkFileName, $output)
            # increment the part counter
            ++$count
        }
        # done, close reader
        $reader.Close()
    }
    catch
    {
        throw "Unable to split file ${Path}: $_"
    }
}

Split-File -Path "C:\path\to\to\files.zip" -PartSizeBytes 1GB -Verbose