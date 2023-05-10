# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

import re, json
from apps import db
from apps.home import blueprint
from flask import request, render_template, redirect, url_for
from flask_login import login_required, current_user
from jinja2 import TemplateNotFound
from apps.authentication.models import Cases, APIs, FileHash
from apps.home.forms import CreateCaseForm, CreateSettingsForm, SubmissionForm
from apps.home.utils import file_scan, hash_scan, urlip_scan, hashid, PyJSON


@blueprint.route('/index')
@login_required
def index():
    cases_count = Cases.query.count()
    return render_template('home/index.html', cases_count=cases_count, segment='index')


@blueprint.route('/<template>')
@login_required
def route_template(template):

    try:

        if not template.endswith('.html'):
            template += '.html'

        # Detect the current page
        segment = get_segment(request)

        # Serve the file (if exists) from app/templates/home/FILE.html
        return render_template("home/" + template, segment=segment)

    except TemplateNotFound:
        return render_template('home/page-404.html'), 404

    except:
        return render_template('home/page-500.html'), 500

@blueprint.route('/newcase', methods=['GET', 'POST'])
@login_required
def newcase():
    create_case_form = CreateCaseForm(request.form)
    if request.method == "POST":

        case_name = request.form.get('case_name')
        # Check casename exists
        case = Cases.query.filter_by(case_name=case_name).first()
        if case:
            return render_template('home/newcase.html',
                                   msg='That Case name already exists',
                                   success=False,
                                   form=create_case_form)
        
        # else we can create the case
        case = Cases(case_name=case_name,user_id=current_user.get_id())
        case.assigned_to = request.form.get('assigned_to')
        case.ticket_id = request.form.get('ticket_id')
        case.case_priority = request.form.get('case_priority')
        case.description = request.form.get('description')
        # Anti-Malware Engines
        case.virustotal = True if request.form.get('virustotal') == "y" else False
        case.anyrun = True if request.form.get('anyrun') == "y" else False
        case.hybridanalysis = True if request.form.get('hybridanalysis') == "y" else False
        case.malwarebazaar = True if request.form.get('malwarebazaar') == "y" else False
        case.alienvault_otx = True if request.form.get('alienvault_otx') == "y" else False
        case.urlscan = True if request.form.get('urlscan') == "y" else False

        db.session.add(case)
        db.session.commit()
        return redirect(url_for('home_blueprint.cases',case_id=case.id))
    else:
        return render_template('home/newcase.html', form=create_case_form)

@blueprint.route('/cases/<int:case_id>', methods=['GET', 'POST'])
@login_required
def cases(case_id):
    case = Cases.query.filter_by(id=case_id, user_id=current_user.get_id()).first_or_404()
    submission_form = SubmissionForm(request.form)
    APIKey = APIs.query.filter_by(user_id=current_user.get_id()).first()

    if request.method == "POST":
        if 'submit_file' in request.form:
            if case.virustotal or case.hybridanalysis:
                # check if the post request has the file part
                # If the user does not select a file, the browser submits an empty file without a filename.
                if 'file' in request.files and request.files['file'].filename != "":
                    file = request.files['file']
                    filename = file.filename
                    file = file.read()
                    sha256 = hashid(file, hash_type="sha256")
                    sha1 = hashid(file, hash_type="sha1")
                    md5 = hashid(file, hash_type="md5")
                    result = file_scan(file, APIKey, filename, sha256)

                    if hasattr(result, 'code'):
                        return render_template(
                        "home/case.html",
                        case=case,
                        form=submission_form,
                        error=result
                        )
                    else:
                        submission = FileHash(user_id=current_user.get_id(), case_id=case.id)
                        submission.case_name = case.case_name
                        submission.file_name = filename
                        submission.data_type = "file"
                        submission.sha256 = sha256
                        submission.sha1 = sha1
                        submission.md5 = md5
                        submission.analysis_id = result.id if hasattr(result, 'id') else None
                        submission.size = result.size if hasattr(result, 'size') else None
                        submission.type = result.type_tag if hasattr(result, 'type_tag') else None
                        submission.scan_status = result.status if hasattr(result, 'status') else "completed"
                        submission.malicious = result.stats['malicious'] if hasattr(result, 'stats') else result.last_analysis_stats['malicious']
                        
                        db.session.add(submission)
                        db.session.commit()
                        return render_template(
                            "home/case.html",
                            case=case,
                            form=submission_form,
                            result=result
                        )
                else:
                    return render_template(
                        "home/case.html",
                        case=case,
                        form=submission_form,
                        error=PyJSON({'code': 'FileSubmissionError', 'message': 'Please submit a valid request and use a valid file name.'})
                    )
            else:
                return render_template(
                    "home/case.html",
                    case=case,
                    form=submission_form,
                    error=PyJSON({'code': 'SandboxError', 'message': 'Please enable Virustotal or Hybrid-analysis and try again.'})
                )
            
        elif 'submit_hash' in request.form:
            if case.virustotal or case.malwarebazaar:
                hash = request.form.get('hash')
                result = hash_scan(hash, APIKey)

                if hasattr(result, 'code'):
                    return render_template(
                    "home/case.html",
                    case=case,
                    form=submission_form,
                    error=result
                    )
                else:
                    submission = FileHash(user_id=current_user.get_id(), case_id=case.id)
                    submission.case_name = case.case_name
                    submission.file_name = json.dumps(result.names) if hasattr(result, 'names') else result.file_name #"unknown" # result.file_name # filename
                    submission.data_type = "hash"
                    submission.sha256 = result.sha256 if hasattr(result, 'sha256') else result.sha256_hash
                    submission.sha1 = result.sha1 if hasattr(result, 'sha1') else result.sha1_hash
                    submission.md5 = result.md5 if hasattr(result, 'md5') else result.md5_hash
                    submission.analysis_id = result.sha256 if hasattr(result, 'sha256') else result.sha256_hash
                    submission.size = result.size if hasattr(result, 'size') else result.file_size
                    submission.type = result.type_tag if hasattr(result, 'type_tag') else result.file_type
                    submission.scan_status = result.status if hasattr(result, 'status') else "completed"
                    submission.malicious = result.stats['malicious'] if hasattr(result, 'stats') else 1
                    
                    db.session.add(submission)
                    db.session.commit()
                    return render_template(
                        "home/case.html",
                        case=case,
                        form=submission_form,
                        result=result
                    )
            else:
                return render_template(
                    "home/case.html",
                    case=case,
                    form=submission_form,
                    error=PyJSON({'code': 'SandboxError', 'message': 'Please enable Virustotal or Malware-Bazaar and try again.'})
                )
            
        elif 'submit_url' in request.form:
            urlip = request.form.get('url')
            url_pattern = "^https?:\\/\\/(?:www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b(?:[-a-zA-Z0-9()@:%_\\+.~#?&\\/=]*)$"
            if re.match(url_pattern, urlip):
                data_type = "url"
            else:
                data_type = "ip"

            result = urlip_scan(urlip, data_type, APIKey)

            return render_template(
                "home/case.html",
                case=case,
                form=submission_form,
                result=result
            )
        
        elif 'submit_pcap' in request.form:
            return render_template(
                "home/case.html",
                case=case,
                form=submission_form,
            )
    else:
        return render_template(
            "home/case.html",
            case=case,
            form=submission_form,
        )

@blueprint.route('/cases/delete/<int:case_id>')
@login_required
def delete_case(case_id):
    case = Cases.query.filter_by(id=case_id, user_id=current_user.get_id()).first_or_404()
    # Admins should not be able to delete themselves
    if case:
        # Notifications.query.filter_by(user_id=user_id).delete()
        # Awards.query.filter_by(user_id=user_id).delete()
        FileHash.query.filter_by(case_id=case_id).delete()
        Cases.query.filter_by(id=case_id).delete()
        db.session.commit()

        allcases = Cases.query.filter_by(user_id=current_user.get_id()).order_by(Cases.id.desc())
        return render_template(
            "home/allcases.html", 
            msg='Case deleted successfully!', 
            cases=allcases
        )
    
    return redirect(url_for('home_blueprint.allcases'))

@blueprint.route('/submission/filehash/delete/<int:submission_id>')
@login_required
def delete_filehash(submission_id):
    submission = FileHash.query.filter_by(id=submission_id, user_id=current_user.get_id()).first_or_404()
    # Admins should not be able to delete themselves
    if submission:
        FileHash.query.filter_by(id=submission_id).delete()
        db.session.commit()
        filehash = FileHash.query.filter_by(user_id=current_user.get_id()).order_by(FileHash.id.desc())
        return render_template(
            "home/submissions.html", 
            msg='Submission deleted successfully!', 
            FileHash=filehash
        )
    return redirect(url_for('home_blueprint.allcases'))

@blueprint.route('/allcases')
@login_required
def allcases():
    allcases = Cases.query.filter_by(user_id=current_user.get_id()).order_by(Cases.id.desc())
    return render_template("home/allcases.html", cases=allcases)

@blueprint.route('/submissions')
@login_required
def submissions():
    filehash = FileHash.query.filter_by(user_id=current_user.get_id()).order_by(FileHash.id.desc())
    return render_template("home/submissions.html", FileHash=filehash)

@blueprint.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    Old_API = APIs.query.filter_by(user_id=current_user.get_id()).first()
    create_settings_form = CreateSettingsForm(request.form)
    if request.method == "POST":

        # Check API exists
        if Old_API:
            Old_API.VTAPI = request.form.get('VTAPI')
            Old_API.HBAPI = request.form.get('HBAPI')
            Old_API.MBAPI = request.form.get('MBAPI')
            Old_API.ARAPI = request.form.get('ARAPI')
            Old_API.URLAPI = request.form.get('URLAPI')
            Old_API.OTXAPI = request.form.get('OTXAPI')

            db.session.add(Old_API)
            db.session.commit()
            return render_template('home/settings.html',
                                   msg='Settings updated successfully',
                                   form=create_settings_form,
                                   API=Old_API)
        
        API = APIs(user_id=current_user.get_id())
        # Anti-Malware API
        API.VTAPI = request.form.get('VTAPI')
        API.HBAPI = request.form.get('HBAPI')
        API.MBAPI = request.form.get('MBAPI')
        API.ARAPI = request.form.get('ARAPI')
        API.URLAPI = request.form.get('URLAPI')
        API.OTXAPI = request.form.get('OTXAPI')

        db.session.add(API)
        db.session.commit()
        return render_template('home/settings.html',
                                   msg='Settings updated successfully',
                                   form=create_settings_form,
                                   API=API)

    else:
        return render_template('home/settings.html', form=create_settings_form, API=Old_API)

# Helper - Extract current page name from request
def get_segment(request):

    try:

        segment = request.path.split('/')[-1]

        if segment == '':
            segment = 'index'

        return segment

    except:
        return None
