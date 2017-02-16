'''
Shawn Hoffman

TODO apply native method type information
'''

import idc
import idaapi
import idautils
import construct
import struct
import io

ImageFileHeader = construct.Struct('ImageFileHeader',
    construct.Enum(construct.ULInt16('Machine'),
        IMAGE_FILE_MACHINE_I386  = 0x014c,
        IMAGE_FILE_MACHINE_AMD64 = 0x8664,
        IMAGE_FILE_MACHINE_ARMNT = 0x01c4
    ),
    construct.ULInt16('NumberOfSections'),
    construct.ULInt32('TimeDateStamp'),
    construct.ULInt32('PointerToSymbolTable'),
    construct.ULInt32('NumberOfSymbols'),
    construct.ULInt16('SizeOfOptionalHeader'),
    construct.ULInt16('Characteristics')
)

def MakeRva(name):
    return construct.Embed(construct.Struct('EmbeddedRva',
        construct.ULInt32(name),
        construct.Value('VA', lambda ctx: idaapi.get_imagebase() + ctx[name])
    ))

def MakeImageDataDirectory(name):
    return construct.Struct(name,
        MakeRva('VirtualAddress'),
        construct.ULInt32('Size')
    )

IMAGE_DIRECTORY_ENTRY_EXPORT         =  0 # Export Directory
IMAGE_DIRECTORY_ENTRY_IMPORT         =  1 # Import Directory
IMAGE_DIRECTORY_ENTRY_RESOURCE       =  2 # Resource Directory
IMAGE_DIRECTORY_ENTRY_EXCEPTION      =  3 # Exception Directory
IMAGE_DIRECTORY_ENTRY_SECURITY       =  4 # Security Directory
IMAGE_DIRECTORY_ENTRY_BASERELOC      =  5 # Base Relocation Table
IMAGE_DIRECTORY_ENTRY_DEBUG          =  6 # Debug Directory
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE   =  7 # Architecture Specific Data
IMAGE_DIRECTORY_ENTRY_GLOBALPTR      =  8 # RVA of GP
IMAGE_DIRECTORY_ENTRY_TLS            =  9 # TLS Directory
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    = 10 # Load Configuration Directory
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   = 11 # Bound Import Directory in headers
IMAGE_DIRECTORY_ENTRY_IAT            = 12 # Import Address Table
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   = 13 # Delay Load Import Descriptors
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14 # COM Runtime descriptor
IMAGE_NUMBEROF_DIRECTORY_ENTRIES     = 16

ImageOptionalHeader = construct.Struct('ImageOptionalHeader',
    construct.Enum(construct.ULInt16('Magic'),
        IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
        IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
    ),
    construct.ULInt8('MajorLinkerVersion'),
    construct.ULInt8('MinorLinkerVersion'),
    construct.ULInt32('SizeOfCode'),
    construct.ULInt32('SizeOfInitializedData'),
    construct.ULInt32('SizeOfUninitializedData'),
    construct.ULInt32('AddressOfEntryPoint'),
    construct.ULInt32('BaseOfCode'),
    construct.If(lambda ctx: ctx.Magic == 'IMAGE_NT_OPTIONAL_HDR32_MAGIC',
        construct.ULInt32('BaseOfData')
    ),
    construct.Switch('ImageBase', lambda ctx: ctx.Magic, {
            'IMAGE_NT_OPTIONAL_HDR32_MAGIC' : construct.ULInt32('ImageBase_'),
            'IMAGE_NT_OPTIONAL_HDR64_MAGIC' : construct.ULInt64('ImageBase_')
        }
    ),
    construct.ULInt32('SectionAlignment'),
    construct.ULInt32('FileAlignment'),
    construct.ULInt16('MajorOperatingSystemVersion'),
    construct.ULInt16('MinorOperatingSystemVersion'),
    construct.ULInt16('MajorImageVersion'),
    construct.ULInt16('MinorImageVersion'),
    construct.ULInt16('MajorSubsystemVersion'),
    construct.ULInt16('MinorSubsystemVersion'),
    construct.ULInt32('Win32VersionValue'),
    construct.ULInt32('SizeOfImage'),
    construct.ULInt32('SizeOfHeaders'),
    construct.ULInt32('CheckSum'),
    construct.ULInt16('Subsystem'),
    construct.ULInt16('DllCharacteristics'),
    # The SizeOf fields should vary size based on Magic, but the PE header read
    # from idautils.peutils_t().header() ALWAYS has them as 32bit. IDA bug?
    construct.ULInt32('SizeOfStackReserve'),
    construct.ULInt32('SizeOfStackCommit'),
    construct.ULInt32('SizeOfHeapReserve'),
    construct.ULInt32('SizeOfHeapCommit'),
    construct.ULInt32('LoaderFlags'),
    construct.ULInt32('NumberOfRvaAndSizes'),
    construct.Array(IMAGE_NUMBEROF_DIRECTORY_ENTRIES, MakeImageDataDirectory('DataDirectory'))
)

ImageNtHeaders = construct.Struct('ImageNtHeaders',
    construct.Magic(b'PE\0\0'), # Signature
    ImageFileHeader,
    ImageOptionalHeader
)

ImageCor20Header = construct.Struct('ImageCor20Header',
    construct.Magic(struct.pack('<L', 0x48)), # Cb
    construct.ULInt16('MajorRuntimeVersion'),
    construct.ULInt16('MinorRuntimeVersion'),
    MakeImageDataDirectory('MetaData'),
    construct.FlagsEnum(construct.ULInt32('Flags'),
        COMIMAGE_FLAGS_ILONLY            = 0x00000001,
        COMIMAGE_FLAGS_32BITREQUIRED     = 0x00000002,
        COMIMAGE_FLAGS_IL_LIBRARY        = 0x00000004,
        COMIMAGE_FLAGS_STRONGNAMESIGNED  = 0x00000008,
        COMIMAGE_FLAGS_NATIVE_ENTRYPOINT = 0x00000010,
        COMIMAGE_FLAGS_TRACKDEBUGDATA    = 0x00010000,
        COMIMAGE_FLAGS_32BITPREFERRED    = 0x00020000
    ),
    construct.Union('EntryPoint',
        construct.ULInt32('EntryPointToken'),
        MakeRva('EntryPointRVA')
    ),
    MakeImageDataDirectory('Resources'),
    MakeImageDataDirectory('StrongNameSignature'),
    MakeImageDataDirectory('CodeManagerTable'),
    MakeImageDataDirectory('VTableFixups'),
    MakeImageDataDirectory('ExportAddressTableJumps'),
    MakeImageDataDirectory('ManagedNativeHeader')
)

StorageSignature = construct.Struct('StorageSignature',
    construct.Magic(b'BSJB'), # lSignature
    construct.ULInt16('iMajorVer'),
    construct.ULInt16('iMinorVer'),
    construct.ULInt32('iExtraData'),
    construct.ULInt32('iVersionString'),
    # don't really care about this string, just makes it more annoying to parse what we care about
    #construct.String('pVersion', lambda ctx: ctx.iVersionString)
)

StorageHeader = construct.Struct('StorageHeader',
    construct.ULInt8('fFlags'),
    construct.Padding(1, strict = True),
    construct.ULInt16('iStreams')
)

MAXSTREAMNAME = 32

StorageStream = construct.Struct('StorageStream',
    # offset from StorageSignature.lSignature
    construct.ULInt32('iOffset'),
    construct.ULInt32('iSize'),
    construct.CString('rcName')
)

MetadataTableHeader = construct.Struct('MetadataTableHeader',
    construct.ULInt32('Reserved'),
    construct.ULInt8('MajorVersion'),
    construct.ULInt8('MinorVersion'),
    construct.FlagsEnum(construct.ULInt8('HeapSizeFlags'),
        StringHeapLarge = 0x01, # 4 byte uint indexes used for string heap offsets
        GUIDHeapLarge   = 0x02, # 4 byte uint indexes used for GUID heap offsets
        BlobHeapLarge   = 0x04, # 4 byte uint indexes used for Blob heap offsets
        EnCDeltas       = 0x20, # Indicates only EnC Deltas are present
        DeletedMarks    = 0x80, # Indicates metadata might contain items marked deleted
    ),
    construct.ULInt8('RowId'),
    construct.ULInt64('ValidTables'),
    construct.ULInt64('SortedTables'),
    construct.Array(lambda ctx: bin(ctx.ValidTables).count('1'), construct.ULInt32('NumRows'))
)

class MDTable:
    Module                  = 0x00
    TypeRef                 = 0x01
    TypeDef                 = 0x02
    FieldPtr                = 0x03
    Field                   = 0x04
    MethodPtr               = 0x05
    Method                  = 0x06
    ParamPtr                = 0x07
    Param                   = 0x08
    InterfaceImpl           = 0x09
    MemberRef               = 0x0A
    Constant                = 0x0B
    CustomAttribute         = 0x0C
    FieldMarshal            = 0x0D
    DeclSecurity            = 0x0E
    ClassLayout             = 0x0F
    FieldLayout             = 0x10
    StandAloneSig           = 0x11
    EventMap                = 0x12
    EventPtr                = 0x13
    Event                   = 0x14
    PropertyMap             = 0x15
    PropertyPtr             = 0x16
    Property                = 0x17
    MethodSemantics         = 0x18
    MethodImpl              = 0x19
    ModuleRef               = 0x1A
    TypeSpec                = 0x1B
    ImplMap                 = 0x1C
    FieldRva                = 0x1D
    EnCLog                  = 0x1E
    EnCMap                  = 0x1F
    Assembly                = 0x20
    AssemblyProcessor       = 0x21
    AssemblyOS              = 0x22
    AssemblyRef             = 0x23
    AssemblyRefProcessor    = 0x24
    AssemblyRefOS           = 0x25
    File                    = 0x26
    ExportedType            = 0x27
    ManifestResource        = 0x28
    NestedClass             = 0x29
    GenericParam            = 0x2A
    MethodSpec              = 0x2B
    GenericParamConstraint  = 0x2C
    # Workaround for CustomAttributeTypeTag having unmapped values
    Invalid                 = 0xff

    @staticmethod
    def get_name(table):
        return {
            MDTable.Module : 'Module',
            MDTable.TypeRef : 'TypeRef',
            MDTable.TypeDef : 'TypeDef',
            MDTable.FieldPtr : 'FieldPtr',
            MDTable.Field : 'Field',
            MDTable.MethodPtr : 'MethodPtr',
            MDTable.Method : 'Method',
            MDTable.ParamPtr : 'ParamPtr',
            MDTable.Param : 'Param',
            MDTable.InterfaceImpl : 'InterfaceImpl',
            MDTable.MemberRef : 'MemberRef',
            MDTable.Constant : 'Constant',
            MDTable.CustomAttribute : 'CustomAttribute',
            MDTable.FieldMarshal : 'FieldMarshal',
            MDTable.DeclSecurity : 'DeclSecurity',
            MDTable.ClassLayout : 'ClassLayout',
            MDTable.FieldLayout : 'FieldLayout',
            MDTable.StandAloneSig : 'StandAloneSig',
            MDTable.EventMap : 'EventMap',
            MDTable.EventPtr : 'EventPtr',
            MDTable.Event : 'Event',
            MDTable.PropertyMap : 'PropertyMap',
            MDTable.PropertyPtr : 'PropertyPtr',
            MDTable.Property : 'Property',
            MDTable.MethodSemantics : 'MethodSemantics',
            MDTable.MethodImpl : 'MethodImpl',
            MDTable.ModuleRef : 'ModuleRef',
            MDTable.TypeSpec : 'TypeSpec',
            MDTable.ImplMap : 'ImplMap',
            MDTable.FieldRva : 'FieldRva',
            MDTable.EnCLog : 'EnCLog',
            MDTable.EnCMap : 'EnCMap',
            MDTable.Assembly : 'Assembly',
            MDTable.AssemblyProcessor : 'AssemblyProcessor',
            MDTable.AssemblyOS : 'AssemblyOS',
            MDTable.AssemblyRef : 'AssemblyRef',
            MDTable.AssemblyRefProcessor : 'AssemblyRefProcessor',
            MDTable.AssemblyRefOS : 'AssemblyRefOS',
            MDTable.File : 'File',
            MDTable.ExportedType : 'ExportedType',
            MDTable.ManifestResource : 'ManifestResource',
            MDTable.NestedClass : 'NestedClass',
            MDTable.GenericParam : 'GenericParam',
            MDTable.MethodSpec : 'MethodSpec',
            MDTable.GenericParamConstraint : 'GenericParamConstraint',
        }.get(table, 'Invalid')

class MethodImplAttributes:
    IL      = 0
    Native  = 1
    OPTIL   = 2
    CodeTypeMask = IL | Native | OPTIL

    Managed     = 0
    Unmanaged   = 4
    ManagedMask = Managed | Unmanaged

    NoInlining      = 0x0008
    ForwardRef      = 0x0010
    Synchronized    = 0x0020
    NoOptimization  = 0x0040
    PreserveSig     = 0x0080
    InternalCall    = 0x1000
    MaxMethodImplVal= 0xffff

def MakeModuleRow():
    return construct.Struct('ModuleRow',
        construct.ULInt16('Generation'),
        MDTag.StringHeapRef.parse('Name'),
        MDTag.GuidHeapRef.parse('MVId'),
        MDTag.GuidHeapRef.parse('EnCId'),
        MDTag.GuidHeapRef.parse('EnCBaseId')
    )
def MakeTypeRefRow():
    return construct.Struct('TypeRefRow',
        MDTag.ResolutionScope.parse('ResolutionScope'),
        MDTag.StringHeapRef.parse('TypeName'),
        MDTag.StringHeapRef.parse('TypeNamespace')
    )
def MakeTypeDefRow():
    return construct.Struct('TypeDefRow',
        construct.ULInt32('Flags'),
        MDTag.StringHeapRef.parse('Name'),
        MDTag.StringHeapRef.parse('Namespace'),
        MDTag.TypeDefOrRef.parse('Extends'),
        MDTag.FieldRef.parse('FieldList'),
        MDTag.MethodRef.parse('MethodList')
    )
def MakeFieldPtrRow():
    return construct.Struct('FieldPtrRow',
        MDTag.ResolutionScope.parse('ResolutionScope'),
        MDTag.StringHeapRef.parse('TypeName'),
        MDTag.StringHeapRef.parse('TypeNamespace')
    )
def MakeFieldRow():
    return construct.Struct('FieldRow',
        construct.ULInt16('Flags'),
        MDTag.StringHeapRef.parse('Name'),
        MDTag.BlobHeapRef.parse('Signature')
    )
def MakeMethodPtrRow():
    return construct.Struct('MethodPtrRow',
        MDTag.MethodRef.parse('Method')
    )
def MakeMethodRow():
    return construct.Struct('MethodRow',
        MakeRva('RVA'),
        construct.ULInt16('ImplFlags'),
        construct.ULInt16('Flags'),
        MDTag.StringHeapRef.parse('Name'),
        MDTag.BlobHeapRef.parse('Signature'),
        MDTag.ParamRef.parse('ParamList')
    )
def MakeParamPtrRow():
    return construct.Struct('ParamPtrRow',
        MDTag.ParamRef.parse('Param')
    )
def MakeParamRow():
    return construct.Struct('ParamRow',
        construct.ULInt16('Flags'),
        construct.ULInt16('Sequence'),
        MDTag.StringHeapRef.parse('Name')
    )
def MakeInterfaceImplRow():
    return construct.Struct('InterfaceImplRow',
        MDTag.TypeDefRId.parse('Class'),
        MDTag.TypeDefOrRef.parse('Interface')
    )
def MakeMemberRefRow():
    return construct.Struct('MemberRefRow',
        MDTag.MemberRefParent.parse('Class'),
        MDTag.StringHeapRef.parse('Name'),
        MDTag.BlobHeapRef.parse('Signature')
    )
def MakeConstantRow():
    return construct.Struct('ConstantRow',
        construct.ULInt8('Type'),
        construct.Padding(1, strict = True),
        MDTag.HasConstant.parse('Parent'),
        MDTag.BlobHeapRef.parse('Value')
    )
def MakeCustomAttributeRow():
    return construct.Struct('CustomAttributeRow',
        MDTag.HasCustomAttribute.parse('Parent'),
        MDTag.CustomAttributeType.parse('Type'),
        MDTag.BlobHeapRef.parse('Value')
    )
def MakeFieldMarshalRow():
    return construct.Struct('FieldMarshalRow',
        MDTag.HasFieldMarshal.parse('Parent'),
        MDTag.BlobHeapRef.parse('NativeType')
    )
def MakeDeclSecurityRow():
    return construct.Struct('DeclSecurityRow',
        construct.ULInt16('Action'),
        MDTag.HasDeclSecurity.parse('Parent'),
        MDTag.BlobHeapRef.parse('PermissionSet')
    )
def MakeClassLayoutRow():
    return construct.Struct('ClassLayoutRow',
        construct.ULInt16('PackingSize'),
        construct.ULInt32('ClassSize'),
        MDTag.TypeDefRId.parse('Parent')
    )
def MakeFieldLayoutRow():
    return construct.Struct('FieldLayoutRow',
        construct.ULInt32('Offset'),
        MDTag.FieldRId.parse('Field')
    )
def MakeStandAloneSigRow():
    return construct.Struct('StandAloneSigRow',
        MDTag.BlobHeapRef.parse('Signature')
    )
def MakeEventMapRow():
    return construct.Struct('EventMapRow',
        MDTag.TypeDefRId.parse('Parent'),
        MDTag.EventRId.parse('EventList')
    )
def MakeEventPtrRow():
    return construct.Struct('EventPtrRow',
        MDTag.EventRef.parse('Event')
    )
def MakeEventRow():
    return construct.Struct('EventRow',
        construct.ULInt16('EventFlags'),
        MDTag.StringHeapRef.parse('Name'),
        MDTag.TypeDefOrRef.parse('EventType')
    )
def MakePropertyMapRow():
    return construct.Struct('PropertyMapRow',
        MDTag.TypeDefRId.parse('Parent'),
        MDTag.PropertyRId.parse('PropertyList')
    )
def MakePropertyPtrRow():
    return construct.Struct('PropertyPtrRow',
        MDTag.PropertyRef.parse('Property')
    )
def MakePropertyRow():
    return construct.Struct('PropertyRow',
        construct.ULInt16('Flags'),
        MDTag.StringHeapRef.parse('Name'),
        MDTag.BlobHeapRef.parse('Type')
    )
def MakeMethodSemanticsRow():
    return construct.Struct('MethodSemanticsRow',
        construct.ULInt16('Flags'),
        MDTag.MethodRId.parse('Method'),
        MDTag.HasSemantics.parse('Association')
    )
def MakeMethodImplRow():
    return construct.Struct('MethodImplRow',
        MDTag.TypeDefRId.parse('Class'),
        MDTag.MethodDefOrRef.parse('MethodBody'),
        MDTag.MethodDefOrRef.parse('MethodDeclaration')
    )
def MakeModuleRefRow():
    return construct.Struct('ModuleRefRow',
        MDTag.StringHeapRef.parse('Name')
    )
def MakeTypeSpecRow():
    return construct.Struct('TypeSpecRow',
        MDTag.BlobHeapRef.parse('Signature')
    )
def MakeImplMapRow():
    return construct.Struct('ImplMapRow',
        construct.ULInt16('MappingFlags'),
        MDTag.MemberForwarded.parse('MemberForwarded'),
        MDTag.StringHeapRef.parse('ImportName'),
        MDTag.ModuleRefRId.parse('ImportScope')
    )
def MakeFieldRvaRow():
    return construct.Struct('FieldRvaRow',
        MakeRva('RVA'),
        MDTag.FieldRId.parse('Field')
    )
def MakeEnCLogRow():
    return construct.Struct('EnCLogRow',
        construct.ULInt32('Token'),
        construct.ULInt32('FuncCode')
    )
def MakeEnCMapRow():
    return construct.Struct('EnCMapRow',
        construct.ULInt32('Token')
    )
def MakeAssemblyRow():
    return construct.Struct('AssemblyRow',
        construct.ULInt32('HashAlgId'),
        construct.ULInt16('MajorVersion'),
        construct.ULInt16('MinorVersion'),
        construct.ULInt16('BuildNumber'),
        construct.ULInt16('RevisionNumber'),
        construct.ULInt32('Flags'),
        MDTag.BlobHeapRef.parse('PublicKey'),
        MDTag.StringHeapRef.parse('Name'),
        MDTag.StringHeapRef.parse('Culture')
    )
def MakeAssemblyProcessorRow():
    return construct.Struct('AssemblyProcessorRow',
        construct.ULInt32('Processor')
    )
def MakeAssemblyOSRow():
    return construct.Struct('AssemblyOSRow',
        construct.ULInt32('OSPlatformID'),
        construct.ULInt32('OSMajorVersion'),
        construct.ULInt32('OSMinorVersion')
    )
def MakeAssemblyRefRow():
    return construct.Struct('AssemblyRefRow',
        construct.ULInt16('MajorVersion'),
        construct.ULInt16('MinorVersion'),
        construct.ULInt16('BuildNumber'),
        construct.ULInt16('RevisionNumber'),
        construct.ULInt32('Flags'),
        MDTag.BlobHeapRef.parse('PublicKeyOrToken'),
        MDTag.StringHeapRef.parse('Name'),
        MDTag.StringHeapRef.parse('Culture'),
        MDTag.BlobHeapRef.parse('HashValue')
    )
def MakeAssemblyRefProcessorRow():
    return construct.Struct('AssemblyRefProcessorRow',
        construct.ULInt32('Processor'),
        MDTag.AssemblyRefRId.parse('AssemblyRef')
    )
def MakeAssemblyRefOSRow():
    return construct.Struct('AssemblyRefOSRow',
        construct.ULInt32('OSPlatformID'),
        construct.ULInt32('OSMajorVersion'),
        construct.ULInt32('OSMinorVersion'),
        MDTag.AssemblyRefRId.parse('AssemblyRef')
    )
def MakeFileRow():
    return construct.Struct('FileRow',
        construct.ULInt32('Flags'),
        MDTag.StringHeapRef.parse('Name'),
        MDTag.BlobHeapRef.parse('HashValue')
    )
def MakeExportedTypeRow():
    return construct.Struct('ExportedTypeRow',
        construct.ULInt32('Flags'),
        construct.ULInt32('TypeDefId'),
        MDTag.StringHeapRef.parse('TypeName'),
        MDTag.StringHeapRef.parse('TypeNamespace'),
        MDTag.Implementation.parse('Implementation')
    )
def MakeManifestResourceRow():
    return construct.Struct('ManifestResourceRow',
        construct.ULInt32('Offset'),
        construct.ULInt32('Flags'),
        MDTag.StringHeapRef.parse('Name'),
        MDTag.Implementation.parse('Implementation')
    )
def MakeNestedClassRow():
    return construct.Struct('NestedClassRow',
        MDTag.TypeDefRId.parse('NestedClass'),
        MDTag.TypeDefRId.parse('EnclosingClass')
    )
def MakeGenericParamRow():
    return construct.Struct('GenericParamRow',
        construct.ULInt16('Number'),
        construct.ULInt16('Flags'),
        MDTag.TypeOrMethodDef.parse('Owner'),
        MDTag.StringHeapRef.parse('Name')
    )
def MakeMethodSpecRow():
    return construct.Struct('MethodSpecRow',
        MDTag.MethodDefOrRef.parse('Method'),
        MDTag.BlobHeapRef.parse('Instantiation')
    )
def MakeGenericParamConstraintRow():
    return construct.Struct('GenericParamConstraintRow',
        MDTag.GenericParamRId.parse('Owner'),
        MDTag.TypeDefOrRef.parse('Constraint')
    )

MetadataParseTable = [
    MakeModuleRow,
    MakeTypeRefRow,
    MakeTypeDefRow,
    MakeFieldPtrRow,
    MakeFieldRow,
    MakeMethodPtrRow,
    MakeMethodRow,
    MakeParamPtrRow,
    MakeParamRow,
    MakeInterfaceImplRow,
    MakeMemberRefRow,
    MakeConstantRow,
    MakeCustomAttributeRow,
    MakeFieldMarshalRow,
    MakeDeclSecurityRow,
    MakeClassLayoutRow,
    MakeFieldLayoutRow,
    MakeStandAloneSigRow,
    MakeEventMapRow,
    MakeEventPtrRow,
    MakeEventRow,
    MakePropertyMapRow,
    MakePropertyPtrRow,
    MakePropertyRow,
    MakeMethodSemanticsRow,
    MakeMethodImplRow,
    MakeModuleRefRow,
    MakeTypeSpecRow,
    MakeImplMapRow,
    MakeFieldRvaRow,
    MakeEnCLogRow,
    MakeEnCMapRow,
    MakeAssemblyRow,
    MakeAssemblyProcessorRow,
    MakeAssemblyOSRow,
    MakeAssemblyRefRow,
    MakeAssemblyRefProcessorRow,
    MakeAssemblyRefOSRow,
    MakeFileRow,
    MakeExportedTypeRow,
    MakeManifestResourceRow,
    MakeNestedClassRow,
    MakeGenericParamRow,
    MakeMethodSpecRow,
    MakeGenericParamConstraintRow
]

class MetadataHeapIndex(object):
    def __init__(s):
        s.parse = None

class MetadataTableIndex(object):
    def __init__(s, ReferencedTable):
        s.tableMask = 1 << ReferencedTable
        s.tableMap = [ReferencedTable]
        s.tagSize = 0
        s.tagMask = 0
        s.largeRowSize = 0x10000
        s.parse = None

class MetadataTagInfo(object):
    def __init__(s, ReferencedTables):
        s.tableMask = 0
        s.tableMap = ReferencedTables
        for referencedTable in s.tableMap:
            if referencedTable == MDTable.Invalid:
                continue
            s.tableMask |= 1 << referencedTable
        s.tagSize = (len(s.tableMap) - 1).bit_length()
        s.tagMask = (1 << s.tagSize) - 1
        s.largeRowSize = 1 << (16 - s.tagSize)
        '''
        print 'references %2i tables (%16x), requires %i bits to index, large row size: %4x' % (
            len(s.tableMap), s.tableMask, s.tagSize, s.largeRowSize)
        '''
        s.parse = None

class MDTag:
    # Index is into one heap
    StringHeapRef = MetadataHeapIndex()
    GuidHeapRef   = MetadataHeapIndex()
    BlobHeapRef   = MetadataHeapIndex()
    # Index is into one table (ptr)
    FieldRef    = MetadataTableIndex(MDTable.FieldPtr)
    MethodRef   = MetadataTableIndex(MDTable.MethodPtr)
    ParamRef    = MetadataTableIndex(MDTable.ParamPtr)
    EventRef    = MetadataTableIndex(MDTable.EventPtr)
    PropertyRef = MetadataTableIndex(MDTable.PropertyPtr)
    # direct row index
    TypeDefRId      = MetadataTableIndex(MDTable.TypeDef)
    FieldRId        = MetadataTableIndex(MDTable.Field)
    EventRId        = MetadataTableIndex(MDTable.Event)
    PropertyRId     = MetadataTableIndex(MDTable.Property)
    MethodRId       = MetadataTableIndex(MDTable.Method)
    ModuleRefRId    = MetadataTableIndex(MDTable.ModuleRef)
    AssemblyRefRId  = MetadataTableIndex(MDTable.AssemblyRef)
    GenericParamRId = MetadataTableIndex(MDTable.GenericParam)
    # InterfaceImpl
    # ClassLayout
    # FieldLayout
    # EventMap
    # PropertyMap
    # MethodSemantics
    # MethodImpl
    # ImplMap
    # FieldRVA
    # AssemblyRefProcessor
    # AssemblyRefOS
    # NestedClass
    # GenericParamConstraint
    # Index is into one of > 1 tables
    TypeDefOrRef        = MetadataTagInfo([MDTable.TypeDef, MDTable.TypeRef, MDTable.TypeSpec])
    HasConstant         = MetadataTagInfo([MDTable.Field, MDTable.Param, MDTable.Property])
    HasCustomAttribute  = MetadataTagInfo([MDTable.Method, MDTable.Field, MDTable.TypeRef, MDTable.TypeDef, MDTable.Param, MDTable.InterfaceImpl, MDTable.MemberRef, MDTable.Module, MDTable.DeclSecurity, MDTable.Property, MDTable.Event, MDTable.StandAloneSig, MDTable.ModuleRef, MDTable.TypeSpec, MDTable.Assembly, MDTable.AssemblyRef, MDTable.File, MDTable.ExportedType, MDTable.ManifestResource, MDTable.GenericParam])
    HasFieldMarshal     = MetadataTagInfo([MDTable.Field, MDTable.Param])
    HasDeclSecurity     = MetadataTagInfo([MDTable.TypeDef, MDTable.Method, MDTable.Assembly])
    MemberRefParent     = MetadataTagInfo([MDTable.TypeDef, MDTable.TypeRef, MDTable.ModuleRef, MDTable.Method, MDTable.TypeSpec])
    HasSemantics        = MetadataTagInfo([MDTable.Event, MDTable.Property])
    MethodDefOrRef      = MetadataTagInfo([MDTable.Method, MDTable.MemberRef])
    MemberForwarded     = MetadataTagInfo([MDTable.Field, MDTable.Method])
    Implementation      = MetadataTagInfo([MDTable.File, MDTable.AssemblyRef, MDTable.ExportedType])
    CustomAttributeType = MetadataTagInfo([MDTable.Invalid, MDTable.Method, MDTable.MemberRef, MDTable.Invalid, MDTable.Invalid])
    ResolutionScope     = MetadataTagInfo([MDTable.Module, MDTable.ModuleRef, MDTable.AssemblyRef, MDTable.TypeRef])
    TypeOrMethodDef     = MetadataTagInfo([MDTable.TypeDef, MDTable.Method])

def MDTagSetupParser(MdHeader):
    MDTag.StringHeapRef.parse = construct.ULInt32 if MdHeader.HeapSizeFlags.StringHeapLarge else construct.ULInt16
    MDTag.GuidHeapRef.parse   = construct.ULInt32 if MdHeader.HeapSizeFlags.GUIDHeapLarge else construct.ULInt16
    MDTag.BlobHeapRef.parse   = construct.ULInt32 if MdHeader.HeapSizeFlags.BlobHeapLarge else construct.ULInt16
    # for each index type,
    for v in MDTag.__dict__.itervalues():
        if isinstance(v, MetadataTableIndex) or isinstance(v, MetadataTagInfo):
            numRowsIdx = 0
            needsLarge = False
            for bitPos in range(len(MetadataParseTable)):
                # if the table is referenced and valid,
                if v.tableMask & MdHeader.ValidTables & (1 << bitPos):
                    # check if the size is large enough to warrant using 32bits instead of 16,
                    if MdHeader.NumRows[numRowsIdx] >= v.largeRowSize:
                        needsLarge = True
                        break
                    numRowsIdx += 1
            # and finally assign .parse to the correct type.
            v.parse = construct.ULInt32 if needsLarge else construct.ULInt16

def ReadVtableFixups(ClrHeader):
    VTableFixup = construct.Struct('VTableFixup',
        MakeRva('RVA'),
        construct.ULInt16('Count'),
        construct.FlagsEnum(construct.ULInt16('Type'),
            COR_VTABLE_32BIT                           = 0x01, # V-table slots are 32-bits in size.
            COR_VTABLE_64BIT                           = 0x02, # V-table slots are 64-bits in size.
            COR_VTABLE_FROM_UNMANAGED                  = 0x04, # If set, transition from unmanaged.
            COR_VTABLE_FROM_UNMANAGED_RETAIN_APPDOMAIN = 0x08, # If set, transition from unmanaged with keeping the current appdomain.
            COR_VTABLE_CALL_MOST_DERIVED               = 0x10, # Call most derived method described by
        )
    )
    numFixups = ClrHeader.VTableFixups.Size / VTableFixup.sizeof()
    VTableFixups = construct.Array(numFixups, VTableFixup)
    if numFixups == 0: return []
    return VTableFixups.parse(idc.GetManyBytes(clrHeader.VTableFixups.VA, VTableFixups.sizeof()))

class MDStreams(object):
    def __init__(s):
        s.streams = {}

    def getStream(s, name):
        return s.streams[name]

    def addStream(s, name, data):
        assert name not in s.streams
        s.streams[name] = io.BytesIO(data)

if __name__ == '__main__':
    peHeader = ImageNtHeaders.parse(idautils.peutils_t().header())
    #print peHeader

    clrDirectory = peHeader.ImageOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR]
    #print '%8x %8x' % (clrDirectory.VA, clrDirectory.Size)
    #Jump(clrHeaderEa)

    clrHeader = ImageCor20Header.parse(idc.GetManyBytes(clrDirectory.VA, ImageCor20Header.sizeof()))
    #print clrHeader

    if clrHeader.Flags.COMIMAGE_FLAGS_NATIVE_ENTRYPOINT:
        idc.AddEntryPoint(clrHeader.EntryPoint.VA, clrHeader.EntryPoint.VA, 'ClrEntryPointNative', True)

    clrMetadataEa = clrHeader.MetaData.VA
    clrVTableFixupsEa = clrHeader.VTableFixups.VA
    print 'metadata %8x vtablefixups %8x' % (clrMetadataEa, clrVTableFixupsEa)

    #Jump(clrMetadataEa)

    clrMetadataHeader = StorageSignature.parse(idc.GetManyBytes(clrMetadataEa, StorageSignature.sizeof()))
    #print clrMetadataHeader

    storageHeaderEa = clrMetadataEa + StorageSignature.sizeof() + ((clrMetadataHeader.iVersionString + 3) & ~3)
    storageHeader = StorageHeader.parse(idc.GetManyBytes(storageHeaderEa, StorageHeader.sizeof()))
    #print storageHeader

    storageStreamEa = storageHeaderEa + StorageHeader.sizeof()
    streams = MDStreams()
    for i in range(storageHeader.iStreams):
        storageStream = StorageStream.parse(idc.GetManyBytes(storageStreamEa, 8 + MAXSTREAMNAME))
        #print '%-32s %8x %8x' % (storageStream.rcName, storageStream.iOffset, storageStream.iSize)
        streams.addStream(storageStream.rcName, idc.GetManyBytes(clrMetadataEa + storageStream.iOffset, storageStream.iSize))
        storageStreamEa += ((8 + len(storageStream.rcName) + 1) + 3) & ~3

    metadataTablesHeap = streams.getStream('#~')
    metadataTableHeader = MetadataTableHeader.parse_stream(metadataTablesHeap)
    #print metadataTableHeader

    MDTagSetupParser(metadataTableHeader)

    metadataTables = [None] * len(MetadataParseTable)

    assert len(MetadataParseTable) <= 64
    numRowsIdx = 0
    print 'Processing metadata...'
    for bitPos in range(len(MetadataParseTable)):
        if metadataTableHeader.ValidTables & (1 << bitPos):
            rowStruct = MetadataParseTable[bitPos]()
            metadataTables[bitPos] = construct.Array(metadataTableHeader.NumRows[numRowsIdx], rowStruct).parse_stream(metadataTablesHeap)
            numRowsIdx += 1

    def getStringFromHeap(index):
        stringHeap = streams.getStream('#Strings')
        stringHeap.seek(index)
        return construct.CString('Name').parse_stream(stringHeap)

    # Apply names for any native methods
    if metadataTables[MDTable.Method] is not None:
        print 'Processing methods...'
        for method in metadataTables[MDTable.Method]:
            if (method.ImplFlags & MethodImplAttributes.CodeTypeMask) == MethodImplAttributes.Native:
                methodName = getStringFromHeap(method.Name)
                #print '%8x %s' % (method.VA, methodName)
                idc.MakeFunction(method.VA)
                idc.MakeNameEx(method.VA, methodName, SN_NOWARN | SN_NOCHECK)

    # Apply field names (to fields with addresses)
    if metadataTables[MDTable.FieldRva] is not None:
        print 'Processing fields...'
        for fieldRva in metadataTables[MDTable.FieldRva]:
            # It seems that all row indexes are 1 based
            field = metadataTables[MDTable.Field][fieldRva.Field - 1]
            fieldName = getStringFromHeap(field.Name)
            #print '%8x %4x %4x %s' % (fieldRva.VA, fieldRva.Field, field.Name, fieldName)
            idc.MakeNameEx(fieldRva.VA, fieldName, SN_NOWARN | SN_NOCHECK)

    # Apply names for vtable slots
    print 'Processing vtablefixups...'
    for vTableFixup in ReadVtableFixups(clrHeader):
        #print '%8x' % (vTableFixup.VA)
        slotEa = vTableFixup.VA
        slotAccessor = idc.Dword if vTableFixup.Type.COR_VTABLE_32BIT else idc.Qword
        slotSize = 4 if vTableFixup.Type.COR_VTABLE_32BIT else 8
        for slot in range(vTableFixup.Count):
            slotToken = slotAccessor(slotEa)
            table = (slotToken >> 24) & 0xff
            index = slotToken & 0xffffff
            method = metadataTables[table][index - 1]
            methodName = getStringFromHeap(method.Name)
            #print '%3i %8x %8x %s' % (slot, slotToken, method.VA, methodName)
            idc.MakeComm(slotEa, methodName)
            if (method.ImplFlags & MethodImplAttributes.CodeTypeMask) == MethodImplAttributes.Native:
                # this should have been found by scanning method table, but anyways...
                idc.MakeFunction(method.VA)
            # always try to set the name (even if it's MSIL)
            idc.MakeNameEx(method.VA, methodName, SN_NOWARN | SN_NOCHECK)
            slotEa += slotSize