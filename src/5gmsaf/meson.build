# License: 5G-MAG Public License (v1.0)
# Author: Dev Audsin
# Copyright: (C) 2022 British Broadcasting Corporation
#
# For full license terms please see the LICENSE file distributed with this
# program. If this file is missing then the license can be retrieved from
# https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view


libapp_dep = open5gs_project.get_variable('libapp_dep')
libcrypt_dep = open5gs_project.get_variable('libcrypt_dep')
libsbi_dep = open5gs_project.get_variable('libsbi_dep')
open5gs_sysconfdir = open5gs_project.get_variable('open5gs_sysconfdir')
srcinc = open5gs_project.get_variable('srcinc')
libdir = open5gs_project.get_variable('libdir')
libmsaf_dist_sources = files('''
    context.c
    context.h
    event.c
    event.h
    sbi-path.c
    sbi-path.h
    msaf-sm.c
    msaf-sm.h
    init.c
    init.h
'''.split())

libmsaf_gen_sources = '''
    openapi/model/caching_configuration.h
    openapi/model/caching_configuration.c
    openapi/model/caching_configuration_caching_directives.h
    openapi/model/caching_configuration_caching_directives.c
    openapi/model/content_hosting_configuration.h
    openapi/model/content_hosting_configuration.c
    openapi/model/distribution_configuration.h
    openapi/model/distribution_configuration.c
    openapi/model/distribution_configuration_geo_fencing.h
    openapi/model/distribution_configuration_geo_fencing.c
    openapi/model/distribution_configuration_supplementary_distribution_networks.h
    openapi/model/distribution_configuration_supplementary_distribution_networks.c
    openapi/model/distribution_configuration_url_signature.h
    openapi/model/distribution_configuration_url_signature.c
    openapi/model/distribution_mode.h
    openapi/model/distribution_mode.c
    openapi/model/distribution_network_type.h
    openapi/model/distribution_network_type.c
    openapi/model/ingest_configuration.h
    openapi/model/ingest_configuration.c
    openapi/model/path_rewrite_rule.h
    openapi/model/path_rewrite_rule.c
    openapi/model/object.c
    openapi/model/object.h
    openapi/model/civic_address.h
    openapi/model/civic_address.c
    openapi/model/eas_discovery_template.h
    openapi/model/eas_discovery_template.c
    openapi/model/eas_relocation_tolerance.h
    openapi/model/eas_relocation_tolerance.c
    openapi/model/ecgi.h
    openapi/model/ecgi.c
    openapi/model/edge_processing_eligibility_criteria.h
    openapi/model/edge_processing_eligibility_criteria.c
    openapi/model/ellipsoid_arc.h
    openapi/model/ellipsoid_arc.c
    openapi/model/ellipsoid_arc_all_of.h
    openapi/model/ellipsoid_arc_all_of.c
    openapi/model/gad_shape.h
    openapi/model/gad_shape.c
    openapi/model/geographic_area.h
    openapi/model/geographic_area.c
    openapi/model/geographical_coordinates.h
    openapi/model/geographical_coordinates.c
    openapi/model/global_ran_node_id.h
    openapi/model/global_ran_node_id.c
    openapi/model/gnb_id.h
    openapi/model/gnb_id.c
    openapi/model/ip_packet_filter_set.h
    openapi/model/ip_packet_filter_set.c
    openapi/model/local2d_point_uncertainty_ellipse.h
    openapi/model/local2d_point_uncertainty_ellipse.c
    openapi/model/local2d_point_uncertainty_ellipse_all_of.h
    openapi/model/local2d_point_uncertainty_ellipse_all_of.c
    openapi/model/local3d_point_uncertainty_ellipsoid.h
    openapi/model/local3d_point_uncertainty_ellipsoid.c
    openapi/model/local3d_point_uncertainty_ellipsoid_all_of.h
    openapi/model/local3d_point_uncertainty_ellipsoid_all_of.c
    openapi/model/local_origin.h
    openapi/model/local_origin.c
    openapi/model/location_area5_g.h
    openapi/model/location_area5_g.c
    openapi/model/m5_eas_relocation_requirements.h
    openapi/model/m5_eas_relocation_requirements.c
    openapi/model/ncgi.h
    openapi/model/ncgi.c
    openapi/model/network_area_info.h
    openapi/model/network_area_info.c
    openapi/model/plmn_id.h
    openapi/model/plmn_id.c
    openapi/model/point.h
    openapi/model/point.c
    openapi/model/point_all_of.h
    openapi/model/point_all_of.c
    openapi/model/point_altitude.h
    openapi/model/point_altitude.c
    openapi/model/point_altitude_all_of.h
    openapi/model/point_altitude_all_of.c
    openapi/model/point_altitude_uncertainty.h
    openapi/model/point_altitude_uncertainty.c
    openapi/model/point_altitude_uncertainty_all_of.h
    openapi/model/point_altitude_uncertainty_all_of.c
    openapi/model/point_uncertainty_circle.h
    openapi/model/point_uncertainty_circle.c
    openapi/model/point_uncertainty_circle_all_of.h
    openapi/model/point_uncertainty_circle_all_of.c
    openapi/model/point_uncertainty_ellipse.h
    openapi/model/point_uncertainty_ellipse.c
    openapi/model/point_uncertainty_ellipse_all_of.h
    openapi/model/point_uncertainty_ellipse_all_of.c
    openapi/model/polygon.h
    openapi/model/polygon.c
    openapi/model/polygon_all_of.h
    openapi/model/polygon_all_of.c
    openapi/model/provisioning_session_type.h
    openapi/model/provisioning_session_type.c
    openapi/model/relative_cartesian_location.h
    openapi/model/relative_cartesian_location.c
    openapi/model/sdf_method.h
    openapi/model/sdf_method.c
    openapi/model/service_access_information_resource.h
    openapi/model/service_access_information_resource.c
    openapi/model/service_access_information_resource_client_consumption_reporting_configuration.h
    openapi/model/service_access_information_resource_client_consumption_reporting_configuration.c
    openapi/model/service_access_information_resource_client_edge_resources_configuration.h
    openapi/model/service_access_information_resource_client_edge_resources_configuration.c
    openapi/model/service_access_information_resource_client_metrics_reporting_configuration.h
    openapi/model/service_access_information_resource_client_metrics_reporting_configuration.c
    openapi/model/service_access_information_resource_dynamic_policy_invocation_configuration.h
    openapi/model/service_access_information_resource_dynamic_policy_invocation_configuration.c
    openapi/model/service_access_information_resource_network_assistance_configuration.h
    openapi/model/service_access_information_resource_network_assistance_configuration.c
    openapi/model/service_access_information_resource_streaming_access.h
    openapi/model/service_access_information_resource_streaming_access.c
    openapi/model/service_data_flow_description.h
    openapi/model/service_data_flow_description.c
    openapi/model/supported_gad_shapes.h
    openapi/model/supported_gad_shapes.c
    openapi/model/tai.h
    openapi/model/tai.c
    openapi/model/time_window.h
    openapi/model/time_window.c
    openapi/model/uncertainty_ellipse.h
    openapi/model/uncertainty_ellipse.c
    openapi/model/uncertainty_ellipsoid.h
    openapi/model/uncertainty_ellipsoid.c
'''.split()

gen_5gmsaf_openapi = find_program('sh')
openapi_gen_result = run_command([gen_5gmsaf_openapi,'-c','$MESON_SOURCE_ROOT/$MESON_SUBDIR/generator-5gmsaf'], check: true, capture: false)

libmsaf_sources = libmsaf_dist_sources + libmsaf_gen_sources

libmsaf = static_library('msaf',
    sources : libmsaf_sources,
    dependencies : [libapp_dep,
                    libcrypt_dep,
                    libsbi_dep],
    install : false)

libmsaf_dep = declare_dependency(
    link_with : libmsaf,
    dependencies : [libapp_dep,
                    libcrypt_dep,
                    libsbi_dep])

msaf_sources = files('''
    app.c
    ../../subprojects/open5gs/src/main.c
'''.split())

executable('open5gs-msafd',
    sources : msaf_sources,
    c_args : '-DDEFAULT_CONFIG_FILENAME="@0@/msaf.yaml"'.format(open5gs_sysconfdir),
    include_directories : srcinc,
    dependencies : [libmsaf_dep],
    install_rpath : libdir,
    install : true)
