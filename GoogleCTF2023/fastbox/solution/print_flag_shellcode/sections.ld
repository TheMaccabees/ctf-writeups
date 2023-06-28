ENTRY(_start)
SECTIONS
{
    .text :
    {
        *(.rdata) *(.text)
    }
}