import logging
from column import Column, Integer, String, DateTime, Keyword

class ModelBase(type):
    columns = {}
    def __new__(cls, name, bases, attr):
        #logging.debug(name)
        #logging.debug(attr.iteritems())
        columns = [y for (x,y) in attr.iteritems() if isinstance(y, Column)]
        for col in columns:
            ModelBase.columns[col.icat_id] = col
        #logging.debug(columns)
        attr['_columns'] = columns
        #attr['_icat_column_names'] = [y.icat_key for (x,y) in columns]
        #logging.debug(attr['_icat_column_names'])
        return type.__new__(cls, name, bases, attr)

class Model(object):
    __metaclass__ = ModelBase

class Zone(Model):
    id = Column(Integer, 'ZONE_ID', 101)
    name = Column(String, 'ZONE_NAME', 102)

class User(Model):
    id = Column(Integer, 'USER_ID', 201)
    name = Column(String, 'USER_NAME', 202)
    type = Column(String, 'USER_TYPE', 203)
    zone = Column(String, 'USER_ZONE', 204)
    dn = Column(String, 'USER_DN', 205)
    info = Column(String, 'USER_INFO', 206)
    comment = Column(String, 'USER_COMMENT', 207)
    create_time = Column(DateTime, 'USER_CREATE_TIME', 208)
    modify_time = Column(DateTime, 'USER_MODIFY_TIME', 209)

class Resource(Model):
    id = Column(Integer, 'R_RESC_ID', 301)
    name = Column(String, 'R_RESC_ID', 302)
    zone_name = Column(String, 'R_ZONE_NAME', 303)
    type = Column(String, 'R_TYPE_NAME', 304)
    class_name = Column(String, 'R_CLASS_NAME', 305)
    location = Column(String, 'R_LOC', 306)
    vault_path = Column(String, 'R_VALUT_PATH', 307)
    free_space = Column(String, 'R_FREE_SPACE', 308)
    info = Column(String, 'R_RESC_INFO', 309)
    comment = Column(String, 'R_RESC_COMMENT', 310)
    create_time = Column(DateTime, 'R_CREATE_TIME', 311)
    modify_time = Column(DateTime, 'R_MODIFY_TIME', 312)

class DataObject(Model):
    id = Column(Integer, 'D_DATA_ID', 401) 
    collection_id = Column(Integer, 'D_COLL_ID', 402)
    name = Column(String, 'DATA_NAME', 403)
    replica_number = Column(Integer, 'DATA_REPL_NUM', 404)
    version = Column(String, 'DATA_VERSION', 405)
    type = Column(String, 'DATA_TYPE_NAME', 406)
    size = Column(Integer, 'DATA_SIZE', 407)
    resource_group_name = Column(String, 'D_RESC_GROUP_NAME', 408)
    resource_name = Column(String, 'D_RESC_NAME', 409)
    path = Column(String, 'D_DATA_PATH', 410)
    owner_name = Column(String, 'D_OWNER_NAME', 411)
    owner_zone = Column(String, 'D_OWNER_ZONE', 412)
    replica_status = Column(String, 'D_REPL_STATUS', 413)
    status = Column(String, 'D_DATA_STATUS', 414)
    checksum = Column(String, 'D_DATA_CHECKSUM', 415)
    expiry = Column(String, 'D_EXPIRY', 416)
    map_id = Column(Integer, 'D_MAP_ID', 417)
    comments = Column(String, 'D_COMMENTS', 418)
    create_time = Column(DateTime, 'D_CREATE_TIME', 419)
    modify_time = Column(DateTime, 'D_MODIFY_TIME', 420)
    
class Collection(Model):
    id = Column(Integer, 'COLL_ID', 500)
    name = Column(String, 'COLL_NAME', 501)
    parent_name = Column(String, 'COLL_PARENT_NAME', 502)
    owner_name = Column(String, 'COLL_OWNER_NAME', 503)
    owner_zone = Column(String, 'COLL_OWNER_ZONE', 504)
    map_id = Column(String, 'COLL_MAP_ID', 505)
    inheritance = Column(String, 'COLL_INHERITANCE', 506)
    comments = Column(String, 'COLL_COMMENTS', 507)
    create_time = Column(DateTime, 'COLL_CREATE_TIME', 508)
    modify_time = Column(DateTime, 'COLL_MODIFY_TIME', 509)

# not really a model. Should be dict instead?
class Keywords(Model):
    data_type = Keyword(String, 'dataType')
    chksum = Keyword(String, 'chksum')