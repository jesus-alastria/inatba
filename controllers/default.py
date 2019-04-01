# -*- coding: utf-8 -*-
import os
import json

# For debugging
#from gluon.debug import dbg
#    dbg.set_trace()


# Main page
def index():
    return dict()

# Slave page
def indexslave():
    return dict()

# Get the page where the master application is
def getstatus():

    # Read the status record
    rows = db(db.sync.name == 'instance1').select(db.sync.status)

    the_status = rows[0].status

    # Return the status
    return the_status

# Store the page and position where the master application is located
def setstatus():

    # Retrieve the status from the request
    current_page = request.post_vars

    # Update the status table
    db.sync.update_or_insert(db.sync.name == 'instance1', name='instance1', status=current_page)

    # Return the status
    return "OK"

# Calculates the hash of the document
#@auth.requires_membership('registrar')
def calculateHash():

    # Set the path to the PDF file
    pdfPath = os.path.join(request.folder,'static', 'files', 'INATBAJointDeclarationofSupport.pdf')

    # Read the file as binary
    with open(pdfPath, "rb") as f:
        the_pdf = f.read()

    # Calculate the hash of the file
    import hashlib
    the_hash = hashlib.sha3_256(the_pdf).hexdigest()

    # Update the hash record
    db.hash.update_or_insert(db.hash.name == 'instance1', name='instance1', the_hash=the_hash)

    # Return the hash
    return dict(the_hash=the_hash)

# Get the hash of the document
def gethashed():

    # Build the file name where we store the hash
    hashFilePath = os.path.join(request.folder,'static', 'files', 'inatbahash.txt')

    # Initialize the hash, just in case the file does not exist
    the_hash = ""

    # Read the file if it exists
    if os.path.exists(hashFilePath):
        with open(hashFilePath, "r") as f:
            the_hash = f.read()

    return dict(the_hash=the_hash)

# ---- Action for login/register/etc (required for auth) -----
def user():
    """
    exposes:
    http://..../[app]/default/user/login
    http://..../[app]/default/user/logout
    http://..../[app]/default/user/register
    http://..../[app]/default/user/profile
    http://..../[app]/default/user/retrieve_password
    http://..../[app]/default/user/change_password
    http://..../[app]/default/user/bulk_register
    use @auth.requires_login()
        @auth.requires_membership('group name')
        @auth.requires_permission('read','table name',record_id)
    to decorate functions that need access control
    also notice there is http://..../[app]/appadmin/manage/auth to allow administrator to manage users
    """
    return dict(form=auth())
