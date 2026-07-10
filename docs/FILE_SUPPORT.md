# File Support

TohuPono treats every source as bytes first.

Supported proof inputs include text, images, audio, video, documents, scripts, archives, APKs, logs, datasets, and binaries. Unknown extensions are acceptable because extension is not identity.

Byte-level identity rules:

- matching SHA-256 means the files are byte-identical;
- differing names do not weaken byte-level integrity;
- differing paths do not weaken byte-level integrity;
- changed bytes produce a different `file_id`.

Metadata extraction is best effort. If MIME or OS timestamp metadata is missing or unreliable, the byte digest remains the source of authority.
