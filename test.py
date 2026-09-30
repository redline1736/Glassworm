from gtts import gTTS
from pydub import AudioSegment
import os

# Read the text
with open("test.txt", "r", encoding="utf-8") as f:
    text = f.read()

# Split into chunks of ~3000 characters, breaking at sentence boundaries
def chunk_text(text, max_len=3000):
    chunks = []
    while len(text) > max_len:
        # Find the last period/newline before max_len
        split_at = text.rfind('.', 0, max_len)
        if split_at == -1:
            split_at = max_len
        chunks.append(text[:split_at + 1].strip())
        text = text[split_at + 1:].strip()
    if text:
        chunks.append(text)
    return chunks

chunks = chunk_text(text)
print(f"Split into {len(chunks)} chunks")

# Generate MP3 for each chunk
files = []
for i, chunk in enumerate(chunks):
    print(f"Generating chunk {i+1}/{len(chunks)} ({len(chunk)} chars)...")
    tts = gTTS(text=chunk, lang='en', slow=False)
    filename = f"part_{i:03d}.mp3"
    tts.save(filename)
    files.append(filename)

# Merge all parts into one MP3
combined = AudioSegment.empty()
for f in files:
    combined += AudioSegment.from_mp3(f)

combined.export("madison.mp3", format="mp3")
print("Done: madison.mp3")

# Clean up part files
for f in files:
    os.remove(f)