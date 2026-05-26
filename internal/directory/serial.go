package directory

func IsRollback(newSerial, cachedSerial uint64) bool {
	return newSerial < cachedSerial
}
