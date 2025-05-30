// Code generated by go-swagger; DO NOT EDIT.

package network_security_groups

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"

	"github.com/IBM-Cloud/power-go-client/power/models"
)

// NewV1NetworkSecurityGroupsMoveMemberPostParams creates a new V1NetworkSecurityGroupsMoveMemberPostParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewV1NetworkSecurityGroupsMoveMemberPostParams() *V1NetworkSecurityGroupsMoveMemberPostParams {
	return &V1NetworkSecurityGroupsMoveMemberPostParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewV1NetworkSecurityGroupsMoveMemberPostParamsWithTimeout creates a new V1NetworkSecurityGroupsMoveMemberPostParams object
// with the ability to set a timeout on a request.
func NewV1NetworkSecurityGroupsMoveMemberPostParamsWithTimeout(timeout time.Duration) *V1NetworkSecurityGroupsMoveMemberPostParams {
	return &V1NetworkSecurityGroupsMoveMemberPostParams{
		timeout: timeout,
	}
}

// NewV1NetworkSecurityGroupsMoveMemberPostParamsWithContext creates a new V1NetworkSecurityGroupsMoveMemberPostParams object
// with the ability to set a context for a request.
func NewV1NetworkSecurityGroupsMoveMemberPostParamsWithContext(ctx context.Context) *V1NetworkSecurityGroupsMoveMemberPostParams {
	return &V1NetworkSecurityGroupsMoveMemberPostParams{
		Context: ctx,
	}
}

// NewV1NetworkSecurityGroupsMoveMemberPostParamsWithHTTPClient creates a new V1NetworkSecurityGroupsMoveMemberPostParams object
// with the ability to set a custom HTTPClient for a request.
func NewV1NetworkSecurityGroupsMoveMemberPostParamsWithHTTPClient(client *http.Client) *V1NetworkSecurityGroupsMoveMemberPostParams {
	return &V1NetworkSecurityGroupsMoveMemberPostParams{
		HTTPClient: client,
	}
}

/*
V1NetworkSecurityGroupsMoveMemberPostParams contains all the parameters to send to the API endpoint

	for the v1 network security groups move member post operation.

	Typically these are written to a http.Request.
*/
type V1NetworkSecurityGroupsMoveMemberPostParams struct {

	/* Body.

	   Parameters for moving a Network Security Group member to another Network Security Group
	*/
	Body *models.NetworkSecurityGroupMoveMember

	/* NetworkSecurityGroupID.

	   Network Security Group ID
	*/
	NetworkSecurityGroupID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the v1 network security groups move member post params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *V1NetworkSecurityGroupsMoveMemberPostParams) WithDefaults() *V1NetworkSecurityGroupsMoveMemberPostParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the v1 network security groups move member post params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *V1NetworkSecurityGroupsMoveMemberPostParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the v1 network security groups move member post params
func (o *V1NetworkSecurityGroupsMoveMemberPostParams) WithTimeout(timeout time.Duration) *V1NetworkSecurityGroupsMoveMemberPostParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the v1 network security groups move member post params
func (o *V1NetworkSecurityGroupsMoveMemberPostParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the v1 network security groups move member post params
func (o *V1NetworkSecurityGroupsMoveMemberPostParams) WithContext(ctx context.Context) *V1NetworkSecurityGroupsMoveMemberPostParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the v1 network security groups move member post params
func (o *V1NetworkSecurityGroupsMoveMemberPostParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the v1 network security groups move member post params
func (o *V1NetworkSecurityGroupsMoveMemberPostParams) WithHTTPClient(client *http.Client) *V1NetworkSecurityGroupsMoveMemberPostParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the v1 network security groups move member post params
func (o *V1NetworkSecurityGroupsMoveMemberPostParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the v1 network security groups move member post params
func (o *V1NetworkSecurityGroupsMoveMemberPostParams) WithBody(body *models.NetworkSecurityGroupMoveMember) *V1NetworkSecurityGroupsMoveMemberPostParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the v1 network security groups move member post params
func (o *V1NetworkSecurityGroupsMoveMemberPostParams) SetBody(body *models.NetworkSecurityGroupMoveMember) {
	o.Body = body
}

// WithNetworkSecurityGroupID adds the networkSecurityGroupID to the v1 network security groups move member post params
func (o *V1NetworkSecurityGroupsMoveMemberPostParams) WithNetworkSecurityGroupID(networkSecurityGroupID string) *V1NetworkSecurityGroupsMoveMemberPostParams {
	o.SetNetworkSecurityGroupID(networkSecurityGroupID)
	return o
}

// SetNetworkSecurityGroupID adds the networkSecurityGroupId to the v1 network security groups move member post params
func (o *V1NetworkSecurityGroupsMoveMemberPostParams) SetNetworkSecurityGroupID(networkSecurityGroupID string) {
	o.NetworkSecurityGroupID = networkSecurityGroupID
}

// WriteToRequest writes these params to a swagger request
func (o *V1NetworkSecurityGroupsMoveMemberPostParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Body != nil {
		if err := r.SetBodyParam(o.Body); err != nil {
			return err
		}
	}

	// path param network_security_group_id
	if err := r.SetPathParam("network_security_group_id", o.NetworkSecurityGroupID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
