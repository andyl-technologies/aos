/* SysV permits unspecified bits above each JNI result's declared width. */
.text

.globl Java_JniReturns_falseValue
.type Java_JniReturns_falseValue, @function
Java_JniReturns_falseValue:
    movabsq $0x1122334455667700, %rax
    ret

.globl Java_JniReturns_trueValue
.type Java_JniReturns_trueValue, @function
Java_JniReturns_trueValue:
    movabsq $0x1122334455667701, %rax
    ret

.globl Java_JniReturns_byteValue
.type Java_JniReturns_byteValue, @function
Java_JniReturns_byteValue:
    movabsq $0x11223344556677fb, %rax
    ret

.globl Java_JniReturns_charValue
.type Java_JniReturns_charValue, @function
Java_JniReturns_charValue:
    movabsq $0x1122334455661234, %rax
    ret

.globl Java_JniReturns_shortValue
.type Java_JniReturns_shortValue, @function
Java_JniReturns_shortValue:
    movabsq $0x112233445566fb2e, %rax
    ret

.section .note.GNU-stack,"",@progbits
