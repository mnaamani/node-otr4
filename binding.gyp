{
  'targets': [
    {
      'target_name': 'otrnat',
      'sources': [ "src/otr.cc" ],
      'libraries': ['-lotr'],
      'library_dirs': [
         '/usr/lib','/usr/local/lib'
      ],
    }
  ]
}
