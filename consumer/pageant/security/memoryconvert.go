package security

import "bytes"

type ReadWriterByteBuffer struct {
	ReadBuffer  *bytes.Buffer
	WriteBuffer *bytes.Buffer
}

func NewReadWriteBuffer(init []byte) ReadWriterByteBuffer {
	return ReadWriterByteBuffer{
		ReadBuffer:  bytes.NewBuffer(init),
		WriteBuffer: new(bytes.Buffer),
	}
}

func (b *ReadWriterByteBuffer) Read(p []byte) (n int, err error) {
	return b.ReadBuffer.Read(p)
}

func (b *ReadWriterByteBuffer) Write(p []byte) (n int, err error) {
	return b.WriteBuffer.Write(p)
}
